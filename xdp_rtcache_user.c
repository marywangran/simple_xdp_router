// xdp_rtcache_user.c

#include <linux/bpf.h>
#include <linux/rtnetlink.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <bpf/bpf.h>
#include <poll.h>
#include <net/if.h>
#include "bpf_util.h"

int sock, sock_arp, flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static int *ifindex_list;
char buf[1024];
static int rtcache_map_fd;

static void int_exit(int sig)
{
	int i = 0;

	for (i = 0; i < 2; i++) {
		bpf_set_link_xdp_fd(ifindex_list[i], -1, flags);
	}
	exit(0);
}

int main(int ac, char **argv)
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	struct bpf_object *obj;
	char filename[256];
	int prog_fd;
	int i = 1;
	struct pollfd fds_route, fds_arp;
	struct sockaddr_nl la, lr;
	struct nlmsghdr *nh;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = filename;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		return 1;

	rtcache_map_fd = bpf_object__find_map_fd_by_name(obj, "rtcache_map");
	ifindex_list = (int *)calloc(2, sizeof(int *));
	ifindex_list[0] = if_nametoindex(argv[1]);
	ifindex_list[1] = if_nametoindex(argv[2]);

	for (i = 0; i < 2; i++) {
		bpf_set_link_xdp_fd(ifindex_list[i], prog_fd, flags);
	}
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	memset(&lr, 0, sizeof(lr));
	lr.nl_family = AF_NETLINK;
	lr.nl_groups = RTMGRP_IPV6_ROUTE | RTMGRP_IPV4_ROUTE | RTMGRP_NOTIFY;
	bind(sock, (struct sockaddr *)&lr, sizeof(lr));
	fds_route.fd = sock;
	fds_route.events = POLL_IN;

	sock_arp = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	
	memset(&la, 0, sizeof(la));
	la.nl_family = AF_NETLINK;
	la.nl_groups = RTMGRP_NEIGH | RTMGRP_NOTIFY;
	bind(sock_arp, (struct sockaddr *)&la, sizeof(la));
	fds_arp.fd = sock_arp;
	fds_arp.events = POLL_IN;

	while (1) {
		memset(buf, 0, sizeof(buf));
		if (poll(&fds_route, 1, 3) == POLL_IN) {
			recv(sock, buf, sizeof(buf), 0);
			nh = (struct nlmsghdr *)buf;
		} else if (poll(&fds_arp, 1, 3) == POLL_IN) {
			recv(sock_arp, buf, sizeof(buf), 0);
			nh = (struct nlmsghdr *)buf;
		}
		if (nh->nlmsg_type == RTM_NEWNEIGH || nh->nlmsg_type == RTM_DELNEIGH ||
			nh->nlmsg_type == RTM_NEWROUTE || nh->nlmsg_type == RTM_DELROUTE) {
			__u32 id = 0, next_id;
			while (bpf_map_get_next_key(rtcache_map_fd, &id, &next_id) == 0) {
				bpf_map_delete_elem(rtcache_map_fd, &next_id);
				id = next_id;
			}
		}
	}
}

