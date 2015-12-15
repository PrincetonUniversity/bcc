
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/pkt_cls.h>

int ebpf_filter(struct __sk_buff* ebpf_packet) {
    if (ebpf_packet->ifindex == 4)
        bpf_clone_redirect(ebpf_packet, 5, 0);
    else if (ebpf_packet->ifindex == 5)
        bpf_clone_redirect(ebpf_packet, 4, 0);
    ebpf_packet->mark = TC_ACT_SHOT; /* always drop, the clone is forwarded */
    return TC_ACT_UNSPEC;
}
