// xdp_rtcache_kern.c
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "bpf_helpers.h"

// 最简单的一个转发表项
struct rt_item {
	int ifindex; // 转发出去的接口
	char eth_source[ETH_ALEN]; // 封装帧的源MAC地址。
	char eth_dest[ETH_ALEN]; // 封装帧的目标MAC地址。
};

// 路由转发表缓存
struct bpf_map_def SEC("maps") rtcache_map = {
	.type = BPF_MAP_TYPE_LRU_HASH, // 采用LRU机制，自动老化表项
	.key_size = sizeof(int),
	.value_size = sizeof(struct rt_item),
	.max_entries = 100,
};

// 递减TTL还是要的
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	u32 check = (__force u32)iph->check;

	check += (__force u32)htons(0x0100);
	iph->check = (__force __sum16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

// 字节码的C程序本身
SEC("xdp_rtcache")
int xdp_rtcache_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup ifib;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct rt_item *pitem = NULL;
	unsigned int daddr = 0;
	u16 h_proto;
	u64 nh_off;
	// 至今不知道如何让ebpf程序支持 "%s"
	char fast_info[] = "Fast path to [%d]\n";
	char slow_info[] = "Slow path to [%d]\n";

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		return XDP_DROP;
	}

	__builtin_memset(&ifib, 0, sizeof(ifib));
	h_proto = eth->h_proto;
	if (h_proto != htons(ETH_P_IP)) {
		return XDP_PASS;
	}

	iph = data + nh_off;

	if (iph + 1 > data_end) {
		return XDP_DROP;
	}

	daddr = iph->daddr;

	pitem = bpf_map_lookup_elem(&rtcache_map, &daddr);
	// 首先精确查找转发表，如果找到就直接转发，不必再经历最长前缀匹配的慢速通配查找
	// 这个动作是可以offload到硬件中的。
	if (pitem) {
		ip_decrease_ttl(iph);
		memcpy(eth->h_dest, pitem->eth_dest, ETH_ALEN);
		memcpy(eth->h_source, pitem->eth_source, ETH_ALEN);
		bpf_trace_printk(fast_info, sizeof(fast_info), pitem->ifindex);
		return bpf_redirect(pitem->ifindex, 0);
	}

	// 否则只能执行最长前缀匹配了
	ifib.family = AF_INET;
	ifib.tos = iph->tos;
	ifib.l4_protocol = iph->protocol;
	ifib.tot_len = ntohs(iph->tot_len);
	ifib.ipv4_src = iph->saddr;
	ifib.ipv4_dst = iph->daddr;
	ifib.ifindex = ctx->ingress_ifindex;

	// 调用eBPF封装的路由查找函数，虽然所谓慢速查找，也依然不会进入协议栈的。
	if (bpf_fib_lookup(ctx, &ifib, sizeof(ifib), 0) == 0) {
		struct rt_item nitem;

		memset(&nitem, 0, sizeof(nitem));
		memcpy(&nitem.eth_dest, ifib.dmac, ETH_ALEN);
		memcpy(&nitem.eth_source, ifib.smac, ETH_ALEN);
		nitem.ifindex = ifib.ifindex;
		// 插入新的表项
		bpf_map_update_elem(&rtcache_map, &daddr, &nitem, BPF_ANY);
		ip_decrease_ttl(iph);
		memcpy(eth->h_dest, ifib.dmac, ETH_ALEN);
		memcpy(eth->h_source, ifib.smac, ETH_ALEN);
		bpf_trace_printk(slow_info, sizeof(slow_info), ifib.ifindex);
		return bpf_redirect(ifib.ifindex, 0);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

