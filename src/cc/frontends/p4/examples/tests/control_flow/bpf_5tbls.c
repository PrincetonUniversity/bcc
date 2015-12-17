
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
struct ebpf_headers_t {
    struct ethernet_t ethernet;
};
struct ebpf_metadata_t {
    struct standard_metadata_t standard_metadata;
};
struct tbl1_key_1 {
    char key_field_0[6];
};
enum tbl1_actions_0 {
    tbl1_edit,
    tbl1__nop,
};
struct tbl1_value_2 {
    u32 action;
    union {
        struct {
        } edit;
        struct {
        } _nop;
    } u;
};
BPF_TABLE("hash", struct tbl1_key_1, struct tbl1_value_2, tbl1, 512);
BPF_TABLE("array", u32, struct tbl1_value_2, ebpf_tbl1_miss, 1);
struct tbl2_key_4 {
    char key_field_0[6];
};
enum tbl2_actions_3 {
    tbl2_edit,
    tbl2__nop,
};
struct tbl2_value_5 {
    u32 action;
    union {
        struct {
        } edit;
        struct {
        } _nop;
    } u;
};
BPF_TABLE("hash", struct tbl2_key_4, struct tbl2_value_5, tbl2, 512);
BPF_TABLE("array", u32, struct tbl2_value_5, ebpf_tbl2_miss, 1);
struct tbl3_key_7 {
    char key_field_0[6];
};
enum tbl3_actions_6 {
    tbl3_edit,
    tbl3__nop,
};
struct tbl3_value_8 {
    u32 action;
    union {
        struct {
        } edit;
        struct {
        } _nop;
    } u;
};
BPF_TABLE("hash", struct tbl3_key_7, struct tbl3_value_8, tbl3, 512);
BPF_TABLE("array", u32, struct tbl3_value_8, ebpf_tbl3_miss, 1);
struct tbl4_key_10 {
    char key_field_0[6];
};
enum tbl4_actions_9 {
    tbl4_edit,
    tbl4__nop,
};
struct tbl4_value_11 {
    u32 action;
    union {
        struct {
        } edit;
        struct {
        } _nop;
    } u;
};
BPF_TABLE("hash", struct tbl4_key_10, struct tbl4_value_11, tbl4, 512);
BPF_TABLE("array", u32, struct tbl4_value_11, ebpf_tbl4_miss, 1);
struct tbl9_key_13 {
    char key_field_0[6];
};
enum tbl9_actions_12 {
    tbl9_forward,
    tbl9__nop,
};
struct tbl9_value_14 {
    u32 action;
    union {
        struct {
            u16 port;
        } forward;
        struct {
        } _nop;
    } u;
};
BPF_TABLE("hash", struct tbl9_key_13, struct tbl9_value_14, tbl9, 512);
BPF_TABLE("array", u32, struct tbl9_value_14, ebpf_tbl9_miss, 1);


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
        goto tbl1_15;
    }
    {
        u8 ebpf_hit;
        struct tbl1_key_1 key;
        struct tbl1_value_2 *value;

        tbl1_15:
        /* construct key */
        memcpy(&key.key_field_0, &ebpf_headers.ethernet.dstAddr, 6);
        ebpf_hit = 1;
        /* perform lookup */
        value = tbl1.lookup(&key);
        if (value == NULL) {
            ebpf_hit = 0;
            /* miss; find default action */
            value = ebpf_tbl1_miss.lookup(&ebpf_zero);
        }
        if (value != NULL) {
            /* run action */
            switch (value->action) {
                case tbl1_edit: 
                {
                    ebpf_headers.ethernet.etherType = ebpf_headers.ethernet.etherType + -1;
                }
                goto tbl2_16;
                case tbl1__nop: 
                {
                }
                goto tbl2_16;
            }
        }
        goto end;
    }
    {
        u8 ebpf_hit;
        struct tbl2_key_4 key;
        struct tbl2_value_5 *value;

        tbl2_16:
        /* construct key */
        memcpy(&key.key_field_0, &ebpf_headers.ethernet.dstAddr, 6);
        ebpf_hit = 1;
        /* perform lookup */
        value = tbl2.lookup(&key);
        if (value == NULL) {
            ebpf_hit = 0;
            /* miss; find default action */
            value = ebpf_tbl2_miss.lookup(&ebpf_zero);
        }
        if (value != NULL) {
            /* run action */
            switch (value->action) {
                case tbl2_edit: 
                {
                    ebpf_headers.ethernet.etherType = ebpf_headers.ethernet.etherType + -1;
                }
                goto tbl3_17;
                case tbl2__nop: 
                {
                }
                goto tbl3_17;
            }
        }
        goto end;
    }
    {
        u8 ebpf_hit;
        struct tbl3_key_7 key;
        struct tbl3_value_8 *value;

        tbl3_17:
        /* construct key */
        memcpy(&key.key_field_0, &ebpf_headers.ethernet.dstAddr, 6);
        ebpf_hit = 1;
        /* perform lookup */
        value = tbl3.lookup(&key);
        if (value == NULL) {
            ebpf_hit = 0;
            /* miss; find default action */
            value = ebpf_tbl3_miss.lookup(&ebpf_zero);
        }
        if (value != NULL) {
            /* run action */
            switch (value->action) {
                case tbl3_edit: 
                {
                    ebpf_headers.ethernet.etherType = ebpf_headers.ethernet.etherType + -1;
                }
                goto tbl4_18;
                case tbl3__nop: 
                {
                }
                goto tbl4_18;
            }
        }
        goto end;
    }
    {
        u8 ebpf_hit;
        struct tbl4_key_10 key;
        struct tbl4_value_11 *value;

        tbl4_18:
        /* construct key */
        memcpy(&key.key_field_0, &ebpf_headers.ethernet.dstAddr, 6);
        ebpf_hit = 1;
        /* perform lookup */
        value = tbl4.lookup(&key);
        if (value == NULL) {
            ebpf_hit = 0;
            /* miss; find default action */
            value = ebpf_tbl4_miss.lookup(&ebpf_zero);
        }
        if (value != NULL) {
            /* run action */
            switch (value->action) {
                case tbl4_edit: 
                {
                    ebpf_headers.ethernet.etherType = ebpf_headers.ethernet.etherType + -1;
                }
                goto tbl9_19;
                case tbl4__nop: 
                {
                }
                goto tbl9_19;
            }
        }
        goto end;
    }
    {
        u8 ebpf_hit;
        struct tbl9_key_13 key;
        struct tbl9_value_14 *value;

        tbl9_19:
        /* construct key */
        memcpy(&key.key_field_0, &ebpf_headers.ethernet.dstAddr, 6);
        ebpf_hit = 1;
        /* perform lookup */
        value = tbl9.lookup(&key);
        if (value == NULL) {
            ebpf_hit = 0;
            /* miss; find default action */
            value = ebpf_tbl9_miss.lookup(&ebpf_zero);
        }
        if (value != NULL) {
            /* run action */
            switch (value->action) {
                case tbl9_forward: 
                {
                    ebpf_metadata.standard_metadata.egress_port = value->u.forward.port;
                }
                goto end;
                case tbl9__nop: 
                {
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
//        }
        bpf_clone_redirect(ebpf_packet, ebpf_metadata.standard_metadata.egress_port, 0);
    }
    
    return TC_ACT_SHOT /* drop packet; clone is forwarded */;
}
