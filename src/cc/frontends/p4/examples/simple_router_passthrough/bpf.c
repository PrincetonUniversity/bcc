
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/pkt_cls.h>
enum ErrorCode {
    p4_pe_no_error,
    p4_pe_index_out_of_bounds,
    p4_pe_out_of_packet,
    p4_pe_header_too_long,
    p4_pe_header_too_short,
    p4_pe_unhandled_select,
    p4_pe_checksum,
};

#define EBPF_MASK(t, w) ((((t)(1)) << (w)) - (t)1)
#define BYTES(w) ((w + 7) / 8)
struct ethernet_t {
    char dstAddr[6]; /* 48 bits */
    char srcAddr[6]; /* 48 bits */
    u16 etherType; /* 16 bits */
    u8 valid; /* 1 bits */
};
struct standard_metadata_t {
    u16 ingress_port; /* 9 bits */
    u32 packet_length; /* 32 bits */
    u16 egress_spec; /* 9 bits */
    u16 egress_port; /* 9 bits */
    u32 egress_instance; /* 32 bits */
    u32 instance_type; /* 32 bits */
    u32 clone_spec; /* 32 bits */
    u8 _padding; /* 5 bits */
};
struct ipv4_t {
    u8 version; /* 4 bits */
    u8 ihl; /* 4 bits */
    u8 diffserv; /* 8 bits */
    u16 totalLen; /* 16 bits */
    u16 identification; /* 16 bits */
    u8 flags; /* 3 bits */
    u16 fragOffset; /* 13 bits */
    u8 ttl; /* 8 bits */
    u8 protocol; /* 8 bits */
    u16 hdrChecksum; /* 16 bits */
    u32 srcAddr; /* 32 bits */
    u32 dstAddr; /* 32 bits */
    u8 valid; /* 1 bits */
};
struct ebpf_headers_t {
    struct ethernet_t ethernet;
    struct ipv4_t ipv4;
};
struct ebpf_metadata_t {
    struct standard_metadata_t standard_metadata;
};
struct fwd_key_1 {
    u16 key_field_0;
};
enum fwd_actions_0 {
    fwd_forward,
};
struct fwd_value_2 {
    u32 action;
    union {
        struct {
            u16 port;
        } forward;
    } u;
};
BPF_TABLE("hash", struct fwd_key_1, struct fwd_value_2, fwd, 512);
BPF_TABLE("array", u32, struct fwd_value_2, ebpf_fwd_miss, 1);


int ebpf_filter(struct __sk_buff* ebpf_packet) {
    struct ebpf_headers_t ebpf_headers = {
        .ethernet = {
            .valid = 0
        },
        .ipv4 = {
            .valid = 0
        },
    };
    struct ebpf_metadata_t ebpf_metadata = {
        .standard_metadata = {
            .ingress_port = 0,
            .packet_length = 0,
            .egress_spec = 0,
            .egress_port = 0,
            .egress_instance = 0,
            .instance_type = 0,
            .clone_spec = 0,
            ._padding = 0,
        },
    };
    unsigned ebpf_packetOffsetInBits = 0;
    enum ErrorCode ebpf_error = p4_pe_no_error;
    u8 ebpf_drop = 0;
    u32 ebpf_zero = 0;

    if (ebpf_packet->ifindex == 4) ebpf_metadata.standard_metadata.ingress_port = 4; else
	if (ebpf_packet->ifindex == 5) ebpf_metadata.standard_metadata.ingress_port = 5; else
	if (ebpf_packet->ifindex == 6) ebpf_metadata.standard_metadata.ingress_port = 6; else
	if (ebpf_packet->ifindex == 7) ebpf_metadata.standard_metadata.ingress_port = 7; else
	if (ebpf_packet->ifindex == 8) ebpf_metadata.standard_metadata.ingress_port = 8; else
	if (ebpf_packet->ifindex == 9) ebpf_metadata.standard_metadata.ingress_port = 9;
    goto start;
    start: {
        goto parse_ethernet;
    }
    parse_ethernet: {
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 48)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ethernet.dstAddr[0] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 0) >> 0));
        ebpf_headers.ethernet.dstAddr[1] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 1) >> 0));
        ebpf_headers.ethernet.dstAddr[2] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 2) >> 0));
        ebpf_headers.ethernet.dstAddr[3] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 3) >> 0));
        ebpf_headers.ethernet.dstAddr[4] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 4) >> 0));
        ebpf_headers.ethernet.dstAddr[5] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 5) >> 0));
        ebpf_packetOffsetInBits += 48;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 48)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ethernet.srcAddr[0] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 0) >> 0));
        ebpf_headers.ethernet.srcAddr[1] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 1) >> 0));
        ebpf_headers.ethernet.srcAddr[2] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 2) >> 0));
        ebpf_headers.ethernet.srcAddr[3] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 3) >> 0));
        ebpf_headers.ethernet.srcAddr[4] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 4) >> 0));
        ebpf_headers.ethernet.srcAddr[5] = (u8)((load_byte(ebpf_packet, (ebpf_packetOffsetInBits / 8) + 5) >> 0));
        ebpf_packetOffsetInBits += 48;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ethernet.etherType = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 16;
        ebpf_headers.ethernet.valid = 1;
        u32 tmp_3 = ebpf_headers.ethernet.etherType;
        if (tmp_3 == 2048)
            goto parse_ipv4;
        else
            goto fwd_4;
    }
    parse_ipv4: {
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 4)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv4.version = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (4)) & EBPF_MASK(u8, 4);
        ebpf_packetOffsetInBits += 4;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 4)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv4.ihl = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0)) & EBPF_MASK(u8, 4);
        ebpf_packetOffsetInBits += 4;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv4.diffserv = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 8;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv4.totalLen = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv4.identification = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 3)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv4.flags = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (5)) & EBPF_MASK(u8, 3);
        ebpf_packetOffsetInBits += 3;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 13)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv4.fragOffset = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0)) & EBPF_MASK(u16, 13);
        ebpf_packetOffsetInBits += 13;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv4.ttl = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 8;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 8)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv4.protocol = ((load_byte(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 8;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv4.hdrChecksum = ((load_half(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 16;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 32)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv4.srcAddr = ((load_word(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 32;
        if (ebpf_packet->len < BYTES(ebpf_packetOffsetInBits + 32)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv4.dstAddr = ((load_word(ebpf_packet, (ebpf_packetOffsetInBits + 0) / 8)) >> (0));
        ebpf_packetOffsetInBits += 32;
        ebpf_headers.ipv4.valid = 1;
        goto fwd_4;
    }
    {
        u8 ebpf_hit;
        struct fwd_key_1 key;
        struct fwd_value_2 *value;

        fwd_4:
        /* construct key */
        key.key_field_0 = (ebpf_metadata.standard_metadata.ingress_port);
        ebpf_hit = 1;
        /* perform lookup */
        value = fwd.lookup(&key);
        if (value == NULL) {
            ebpf_hit = 0;
            /* miss; find default action */
            value = ebpf_fwd_miss.lookup(&ebpf_zero);
        }
        if (value != NULL) {
            /* run action */
            switch (value->action) {
                case fwd_forward: 
                {
                    ebpf_metadata.standard_metadata.egress_port = value->u.forward.port;
                }
                goto end;
            }
        }
        goto end;
    }
    end:
    if (!ebpf_drop) {
//        {
//            /* Deparser */
//            ebpf_packetOffsetInBits = 0;
//            if (ebpf_headers.ethernet.valid) {
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers.ethernet.dstAddr[0]);
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 1, 0, 8, ebpf_headers.ethernet.dstAddr[1]);
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 2, 0, 8, ebpf_headers.ethernet.dstAddr[2]);
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 3, 0, 8, ebpf_headers.ethernet.dstAddr[3]);
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 4, 0, 8, ebpf_headers.ethernet.dstAddr[4]);
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 5, 0, 8, ebpf_headers.ethernet.dstAddr[5]);
//                ebpf_packetOffsetInBits += 48;
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers.ethernet.srcAddr[0]);
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 1, 0, 8, ebpf_headers.ethernet.srcAddr[1]);
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 2, 0, 8, ebpf_headers.ethernet.srcAddr[2]);
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 3, 0, 8, ebpf_headers.ethernet.srcAddr[3]);
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 4, 0, 8, ebpf_headers.ethernet.srcAddr[4]);
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 5, 0, 8, ebpf_headers.ethernet.srcAddr[5]);
//                ebpf_packetOffsetInBits += 48;
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers.ethernet.etherType);
//                ebpf_packetOffsetInBits += 16;
//            }
//            if (ebpf_headers.ipv4.valid) {
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 4, ebpf_headers.ipv4.version);
//                ebpf_packetOffsetInBits += 4;
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 4, 4, ebpf_headers.ipv4.ihl);
//                ebpf_packetOffsetInBits += 4;
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers.ipv4.diffserv);
//                ebpf_packetOffsetInBits += 8;
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers.ipv4.totalLen);
//                ebpf_packetOffsetInBits += 16;
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers.ipv4.identification);
//                ebpf_packetOffsetInBits += 16;
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 3, ebpf_headers.ipv4.flags);
//                ebpf_packetOffsetInBits += 3;
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 3, 13, ebpf_headers.ipv4.fragOffset);
//                ebpf_packetOffsetInBits += 13;
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers.ipv4.ttl);
//                ebpf_packetOffsetInBits += 8;
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers.ipv4.protocol);
//                ebpf_packetOffsetInBits += 8;
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers.ipv4.hdrChecksum);
//                ebpf_packetOffsetInBits += 16;
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 32, ebpf_headers.ipv4.srcAddr);
//                ebpf_packetOffsetInBits += 32;
//                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 32, ebpf_headers.ipv4.dstAddr);
//                ebpf_packetOffsetInBits += 32;
//            }
//        }
        bpf_clone_redirect(ebpf_packet, ebpf_metadata.standard_metadata.egress_port, 0);
    }
    
    return TC_ACT_SHOT /* drop packet; clone is forwarded */;
}
