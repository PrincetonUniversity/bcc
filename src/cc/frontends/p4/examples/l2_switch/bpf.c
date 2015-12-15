
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
struct intrinsic_metadata_t {
    u8 mcast_grp; /* 4 bits */
    u8 egress_rid; /* 4 bits */
    u16 mcast_hash; /* 16 bits */
    u32 lf_field_list; /* 32 bits */
};
struct ebpf_headers_t {
    struct ethernet_t ethernet;
};
struct ebpf_metadata_t {
    struct standard_metadata_t standard_metadata;
    struct intrinsic_metadata_t intrinsic_metadata;
};
struct smac_key_1 {
    char key_field_0[6];
};
enum smac_actions_0 {
    smac_mac_learn,
    smac__nop,
};
struct smac_value_2 {
    u32 action;
    union {
        struct {
        } mac_learn;
        struct {
        } _nop;
    } u;
};
BPF_TABLE("hash", struct smac_key_1, struct smac_value_2, smac, 512);
BPF_TABLE("array", u32, struct smac_value_2, ebpf_smac_miss, 1);
struct dmac_key_4 {
    char key_field_0[6];
};
enum dmac_actions_3 {
    dmac_forward,
    dmac_broadcast,
};
struct dmac_value_5 {
    u32 action;
    union {
        struct {
            u16 port;
        } forward;
        struct {
        } broadcast;
    } u;
};
BPF_TABLE("hash", struct dmac_key_4, struct dmac_value_5, dmac, 512);
BPF_TABLE("array", u32, struct dmac_value_5, ebpf_dmac_miss, 1);
struct mcast_src_pruning_key_7 {
    u16 key_field_0;
};
enum mcast_src_pruning_actions_6 {
    mcast_src_pruning__nop,
    mcast_src_pruning__drop,
};
struct mcast_src_pruning_value_8 {
    u32 action;
    union {
        struct {
        } _nop;
        struct {
        } _drop;
    } u;
};
BPF_TABLE("hash", struct mcast_src_pruning_key_7, struct mcast_src_pruning_value_8, mcast_src_pruning, 512);
BPF_TABLE("array", u32, struct mcast_src_pruning_value_8, ebpf_mcast_src_pruning_miss, 1);


int ebpf_filter(struct __sk_buff* ebpf_packet) {
    struct ebpf_headers_t ebpf_headers = {
        .ethernet = {
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
        .intrinsic_metadata = {
            .mcast_grp = 0,
            .egress_rid = 0,
            .mcast_hash = 0,
            .lf_field_list = 0,
        },
    };
    unsigned ebpf_packetOffsetInBits = 0;
    enum ErrorCode ebpf_error = p4_pe_no_error;
    u8 ebpf_drop = 0;
    u32 ebpf_zero = 0;

    ebpf_metadata.standard_metadata.ingress_port = ebpf_packet->ifindex;
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
        goto smac_9;
    }
    {
        u8 ebpf_hit;
        struct smac_key_1 key;
        struct smac_value_2 *value;

        smac_9:
        /* construct key */
        memcpy(&key.key_field_0, &ebpf_headers.ethernet.srcAddr, 6);
        ebpf_hit = 1;
        /* perform lookup */
        value = smac.lookup(&key);
        if (value == NULL) {
            ebpf_hit = 0;
            /* miss; find default action */
            value = ebpf_smac_miss.lookup(&ebpf_zero);
        }
        if (value != NULL) {
            /* run action */
            switch (value->action) {
                case smac_mac_learn: 
                {
                }
                goto dmac_10;
                case smac__nop: 
                {
                }
                goto dmac_10;
            }
        }
        goto end;
    }
    {
        u8 ebpf_hit;
        struct dmac_key_4 key;
        struct dmac_value_5 *value;

        dmac_10:
        /* construct key */
        memcpy(&key.key_field_0, &ebpf_headers.ethernet.dstAddr, 6);
        ebpf_hit = 1;
        /* perform lookup */
        value = dmac.lookup(&key);
        if (value == NULL) {
            ebpf_hit = 0;
            /* miss; find default action */
            value = ebpf_dmac_miss.lookup(&ebpf_zero);
        }
        if (value != NULL) {
            /* run action */
            switch (value->action) {
                case dmac_forward: 
                {
                    ebpf_metadata.standard_metadata.egress_port = value->u.forward.port;
                }
                goto mcast_src_pruning_11;
                case dmac_broadcast: 
                {
                }
                goto mcast_src_pruning_11;
            }
        }
        goto end;
    }
    {
        u8 ebpf_hit;
        struct mcast_src_pruning_key_7 key;
        struct mcast_src_pruning_value_8 *value;

        mcast_src_pruning_11:
        /* construct key */
        key.key_field_0 = (ebpf_metadata.standard_metadata.egress_port);
        ebpf_hit = 1;
        /* perform lookup */
        value = mcast_src_pruning.lookup(&key);
        if (value == NULL) {
            ebpf_hit = 0;
            /* miss; find default action */
            value = ebpf_mcast_src_pruning_miss.lookup(&ebpf_zero);
        }
        if (value != NULL) {
            /* run action */
            switch (value->action) {
                case mcast_src_pruning__nop: 
                {
                }
                goto end;
                case mcast_src_pruning__drop: 
                {
                    ebpf_drop = 1;
                }
                goto end;
            }
        }
        goto end;
    }
    end:
    if (!ebpf_drop) {
        {
            /* Deparser */
            ebpf_packetOffsetInBits = 0;
            if (ebpf_headers.ethernet.valid) {
                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers.ethernet.dstAddr[0]);
                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 1, 0, 8, ebpf_headers.ethernet.dstAddr[1]);
                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 2, 0, 8, ebpf_headers.ethernet.dstAddr[2]);
                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 3, 0, 8, ebpf_headers.ethernet.dstAddr[3]);
                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 4, 0, 8, ebpf_headers.ethernet.dstAddr[4]);
                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 5, 0, 8, ebpf_headers.ethernet.dstAddr[5]);
                ebpf_packetOffsetInBits += 48;
                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers.ethernet.srcAddr[0]);
                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 1, 0, 8, ebpf_headers.ethernet.srcAddr[1]);
                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 2, 0, 8, ebpf_headers.ethernet.srcAddr[2]);
                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 3, 0, 8, ebpf_headers.ethernet.srcAddr[3]);
                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 4, 0, 8, ebpf_headers.ethernet.srcAddr[4]);
                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 5, 0, 8, ebpf_headers.ethernet.srcAddr[5]);
                ebpf_packetOffsetInBits += 48;
                bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers.ethernet.etherType);
                ebpf_packetOffsetInBits += 16;
            }
        }
        if (ebpf_metadata.intrinsic_metadata.mcast_grp == 1) {
            if (ebpf_metadata.standard_metadata.ingress_port != 4)
                bpf_clone_redirect(ebpf_packet, 4, 0);
            if (ebpf_metadata.standard_metadata.ingress_port != 5)
                bpf_clone_redirect(ebpf_packet, 5, 0);
            if (ebpf_metadata.standard_metadata.ingress_port != 6)
                bpf_clone_redirect(ebpf_packet, 6, 0);
            if (ebpf_metadata.standard_metadata.ingress_port != 7)
                bpf_clone_redirect(ebpf_packet, 7, 0);
            if (ebpf_metadata.standard_metadata.ingress_port != 8)
                bpf_clone_redirect(ebpf_packet, 8, 0);
            if (ebpf_metadata.standard_metadata.ingress_port != 9)
                bpf_clone_redirect(ebpf_packet, 9, 0);
        }
        else
        bpf_clone_redirect(ebpf_packet, ebpf_metadata.standard_metadata.egress_port, 0);
    }
    
    return TC_ACT_SHOT /* drop packet; clone is forwarded */;
}
