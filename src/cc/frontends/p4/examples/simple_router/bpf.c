
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
struct routing_metadata_t {
    u32 nhop_ipv4; /* 32 bits */
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
    struct routing_metadata_t routing_metadata;
};
struct ipv4_key_1 {
    u32 key_field_0;
};
enum ipv4_actions_0 {
    ipv4_set_nhop,
    ipv4__drop,
};
struct ipv4_value_2 {
    u32 action;
    union {
        struct {
            u32 nhop_ipv4;
            u16 port;
        } set_nhop;
        struct {
        } _drop;
    } u;
};
BPF_TABLE("hash", struct ipv4_key_1, struct ipv4_value_2, ipv4, 1024);
BPF_TABLE("array", u32, struct ipv4_value_2, ebpf_ipv4_miss, 1);
struct forward_key_4 {
    u32 key_field_0;
};
enum forward_actions_3 {
    forward_set_dmac,
    forward__drop,
};
struct forward_value_5 {
    u32 action;
    union {
        struct {
            char dmac[6];
        } set_dmac;
        struct {
        } _drop;
    } u;
};
BPF_TABLE("hash", struct forward_key_4, struct forward_value_5, forward, 512);
BPF_TABLE("array", u32, struct forward_value_5, ebpf_forward_miss, 1);
struct send_frame_key_7 {
    u16 key_field_0;
};
enum send_frame_actions_6 {
    send_frame_rewrite_mac,
    send_frame__drop,
};
struct send_frame_value_8 {
    u32 action;
    union {
        struct {
            char smac[6];
        } rewrite_mac;
        struct {
        } _drop;
    } u;
};
BPF_TABLE("hash", struct send_frame_key_7, struct send_frame_value_8, send_frame, 256);
BPF_TABLE("array", u32, struct send_frame_value_8, ebpf_send_frame_miss, 1);

/* @Shahbaz: has to be 16 bit wide */
struct ipv4_checksum_list_t {
	u8 version_ihl;
	u8 diffserv;
	u16 totalLen;
	u16 identification;
	u16 flags_fragOffset;
    u8 ttl;
    u8 protocol;
    u32 srcAddr;
	u32 dstAddr;
};


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
        .routing_metadata = {
            .nhop_ipv4 = 0,
        },
    };

    /* @Shahbaz: */
    struct ipv4_checksum_list_t ipv4_checksum_list_old = {
    	.version_ihl = 0,
		.diffserv = 0,
		.totalLen = 0,
		.identification = 0,
		.flags_fragOffset = 0,
    	.ttl = 0,
		.protocol = 0,
		.srcAddr = 0,
		.dstAddr = 0,
    };
    struct ipv4_checksum_list_t ipv4_checksum_list_new = {
		.version_ihl = 0,
		.diffserv = 0,
		.totalLen = 0,
		.identification = 0,
		.flags_fragOffset = 0,
    	.ttl = 0,
    	.protocol = 0,
		.srcAddr = 0,
		.dstAddr = 0,
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
        u32 tmp_9 = ebpf_headers.ethernet.etherType;
        if (tmp_9 == 2048)
            goto parse_ipv4;
        else
            goto ipv4_10;
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
        goto ipv4_10;
    }
    {
        u8 ebpf_hit;
        struct ipv4_key_1 key;
        struct ipv4_value_2 *value;

        ipv4_10:

		/* @Shahbaz: */
		{
			ipv4_checksum_list_old.version_ihl |= (ebpf_headers.ipv4.version << (4));
			ipv4_checksum_list_old.version_ihl |= (ebpf_headers.ipv4.ihl);
			ipv4_checksum_list_old.diffserv |= (ebpf_headers.ipv4.diffserv);
			ipv4_checksum_list_old.totalLen |= (ebpf_headers.ipv4.totalLen);
			ipv4_checksum_list_old.identification |= (ebpf_headers.ipv4.identification);
			ipv4_checksum_list_old.flags_fragOffset |= (ebpf_headers.ipv4.flags << (13));
			ipv4_checksum_list_old.flags_fragOffset |= (ebpf_headers.ipv4.fragOffset);
			ipv4_checksum_list_old.ttl |= (ebpf_headers.ipv4.ttl);
			ipv4_checksum_list_old.protocol |= (ebpf_headers.ipv4.protocol);
			ipv4_checksum_list_old.srcAddr |= (ebpf_headers.ipv4.srcAddr);
			ipv4_checksum_list_old.dstAddr |= (ebpf_headers.ipv4.dstAddr);
		}

        /* construct key */
        key.key_field_0 = (ebpf_headers.ipv4.dstAddr);
        ebpf_hit = 1;
        /* perform lookup */
        value = ipv4.lookup(&key);
        if (value == NULL) {
            ebpf_hit = 0;
            /* miss; find default action */
            value = ebpf_ipv4_miss.lookup(&ebpf_zero);
        }
        if (value != NULL) {
            /* run action */
            switch (value->action) {
                case ipv4_set_nhop: 
                {
                    ebpf_metadata.routing_metadata.nhop_ipv4 = value->u.set_nhop.nhop_ipv4;
                    ebpf_metadata.standard_metadata.egress_port = value->u.set_nhop.port;
                    ebpf_headers.ipv4.ttl = ebpf_headers.ipv4.ttl + -1;
                }
                goto forward_11;
                case ipv4__drop: 
                {
                    ebpf_drop = 1;
                }
                goto forward_11;
            }
        }
        goto end;
    }
    {
        u8 ebpf_hit;
        struct forward_key_4 key;
        struct forward_value_5 *value;

        forward_11:
        /* construct key */
        key.key_field_0 = (ebpf_metadata.routing_metadata.nhop_ipv4);
        ebpf_hit = 1;
        /* perform lookup */
        value = forward.lookup(&key);
        if (value == NULL) {
            ebpf_hit = 0;
            /* miss; find default action */
            value = ebpf_forward_miss.lookup(&ebpf_zero);
        }
        if (value != NULL) {
            /* run action */
            switch (value->action) {
                case forward_set_dmac: 
                {
                    memcpy(&ebpf_headers.ethernet.dstAddr, &value->u.set_dmac.dmac, 6);
                }
                goto send_frame_12;
                case forward__drop: 
                {
                    ebpf_drop = 1;
                }
                goto send_frame_12;
            }
        }
        goto end;
    }
    {
        u8 ebpf_hit;
        struct send_frame_key_7 key;
        struct send_frame_value_8 *value;

        send_frame_12:
        /* construct key */
        key.key_field_0 = (ebpf_metadata.standard_metadata.egress_port);
        ebpf_hit = 1;
        /* perform lookup */
        value = send_frame.lookup(&key);
        if (value == NULL) {
            ebpf_hit = 0;
            /* miss; find default action */
            value = ebpf_send_frame_miss.lookup(&ebpf_zero);
        }
        if (value != NULL) {
            /* run action */
            switch (value->action) {
                case send_frame_rewrite_mac: 
                {
                    memcpy(&ebpf_headers.ethernet.srcAddr, &value->u.rewrite_mac.smac, 6);
                }
                goto end;
                case send_frame__drop: 
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

    	/* @Shahbaz: */
		{
			ipv4_checksum_list_new.version_ihl |= (ebpf_headers.ipv4.version << (4));
			ipv4_checksum_list_new.version_ihl |= (ebpf_headers.ipv4.ihl);
			ipv4_checksum_list_new.diffserv |= (ebpf_headers.ipv4.diffserv);
			ipv4_checksum_list_new.totalLen |= (ebpf_headers.ipv4.totalLen);
			ipv4_checksum_list_new.identification |= (ebpf_headers.ipv4.identification);
			ipv4_checksum_list_new.flags_fragOffset |= (ebpf_headers.ipv4.flags << (13));
			ipv4_checksum_list_new.flags_fragOffset |= (ebpf_headers.ipv4.fragOffset);
			ipv4_checksum_list_new.ttl |= (ebpf_headers.ipv4.ttl);
			ipv4_checksum_list_new.protocol |= (ebpf_headers.ipv4.protocol);
			ipv4_checksum_list_new.srcAddr |= (ebpf_headers.ipv4.srcAddr);
			ipv4_checksum_list_new.dstAddr |= (ebpf_headers.ipv4.dstAddr);

			u16 *ipv4_checksum_list_old_u16 = (u16 *) &ipv4_checksum_list_old;
			u16 *ipv4_checksum_list_new_u16 = (u16 *) &ipv4_checksum_list_new;
			u32 sum = ntohs(*ipv4_checksum_list_old_u16) + ntohs(~*ipv4_checksum_list_new_u16 & 0xffff);
			sum += ebpf_headers.ipv4.hdrChecksum;
			sum = (sum & 0xffff) + (sum >> 16);
			ebpf_headers.ipv4.hdrChecksum = sum + (sum >> 16);

			ipv4_checksum_list_old_u16++;
			ipv4_checksum_list_new_u16++;
			sum = ntohs(*ipv4_checksum_list_old_u16) + ntohs(~*ipv4_checksum_list_new_u16 & 0xffff);
			sum += ebpf_headers.ipv4.hdrChecksum;
			sum = (sum & 0xffff) + (sum >> 16);
			ebpf_headers.ipv4.hdrChecksum = sum + (sum >> 16);

			ipv4_checksum_list_old_u16++;
			ipv4_checksum_list_new_u16++;
			sum = ntohs(*ipv4_checksum_list_old_u16) + ntohs(~*ipv4_checksum_list_new_u16 & 0xffff);
			sum += ebpf_headers.ipv4.hdrChecksum;
			sum = (sum & 0xffff) + (sum >> 16);
			ebpf_headers.ipv4.hdrChecksum = sum + (sum >> 16);

			ipv4_checksum_list_old_u16++;
			ipv4_checksum_list_new_u16++;
			sum = ntohs(*ipv4_checksum_list_old_u16) + ntohs(~*ipv4_checksum_list_new_u16 & 0xffff);
			sum += ebpf_headers.ipv4.hdrChecksum;
			sum = (sum & 0xffff) + (sum >> 16);
			ebpf_headers.ipv4.hdrChecksum = sum + (sum >> 16);

			ipv4_checksum_list_old_u16++;
			ipv4_checksum_list_new_u16++;
			sum = ntohs(*ipv4_checksum_list_old_u16) + ntohs(~*ipv4_checksum_list_new_u16 & 0xffff);
			sum += ebpf_headers.ipv4.hdrChecksum;
			sum = (sum & 0xffff) + (sum >> 16);
			ebpf_headers.ipv4.hdrChecksum = sum + (sum >> 16);

			ipv4_checksum_list_old_u16++;
			ipv4_checksum_list_new_u16++;
			sum = ntohs(*ipv4_checksum_list_old_u16) + ntohs(~*ipv4_checksum_list_new_u16 & 0xffff);
			sum += ebpf_headers.ipv4.hdrChecksum;
			sum = (sum & 0xffff) + (sum >> 16);
			ebpf_headers.ipv4.hdrChecksum = sum + (sum >> 16);

			ipv4_checksum_list_old_u16++;
			ipv4_checksum_list_new_u16++;
			sum = ntohs(*ipv4_checksum_list_old_u16) + ntohs(~*ipv4_checksum_list_new_u16 & 0xffff);
			sum += ebpf_headers.ipv4.hdrChecksum;
			sum = (sum & 0xffff) + (sum >> 16);
			ebpf_headers.ipv4.hdrChecksum = sum + (sum >> 16);

			ipv4_checksum_list_old_u16++;
			ipv4_checksum_list_new_u16++;
			sum = ntohs(*ipv4_checksum_list_old_u16) + ntohs(~*ipv4_checksum_list_new_u16 & 0xffff);
			sum += ebpf_headers.ipv4.hdrChecksum;
			sum = (sum & 0xffff) + (sum >> 16);
			ebpf_headers.ipv4.hdrChecksum = sum + (sum >> 16);

			ipv4_checksum_list_old_u16++;
			ipv4_checksum_list_new_u16++;
			sum = ntohs(*ipv4_checksum_list_old_u16) + ntohs(~*ipv4_checksum_list_new_u16 & 0xffff);
			sum += ebpf_headers.ipv4.hdrChecksum;
			sum = (sum & 0xffff) + (sum >> 16);
			ebpf_headers.ipv4.hdrChecksum = sum + (sum >> 16);
		}

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
			if (ebpf_headers.ipv4.valid) {
				bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 4, ebpf_headers.ipv4.version);
				ebpf_packetOffsetInBits += 4;
				bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 4, 4, ebpf_headers.ipv4.ihl);
				ebpf_packetOffsetInBits += 4;
				bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers.ipv4.diffserv);
				ebpf_packetOffsetInBits += 8;
				bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers.ipv4.totalLen);
				ebpf_packetOffsetInBits += 16;
				bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers.ipv4.identification);
				ebpf_packetOffsetInBits += 16;
				bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 3, ebpf_headers.ipv4.flags);
				ebpf_packetOffsetInBits += 3;
				bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 3, 13, ebpf_headers.ipv4.fragOffset);
				ebpf_packetOffsetInBits += 13;
				bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers.ipv4.ttl);
				ebpf_packetOffsetInBits += 8;
				bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 8, ebpf_headers.ipv4.protocol);
				ebpf_packetOffsetInBits += 8;
				bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 16, ebpf_headers.ipv4.hdrChecksum);
				ebpf_packetOffsetInBits += 16;
				bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 32, ebpf_headers.ipv4.srcAddr);
				ebpf_packetOffsetInBits += 32;
				bpf_dins_pkt(ebpf_packet, ebpf_packetOffsetInBits / 8 + 0, 0, 32, ebpf_headers.ipv4.dstAddr);
				ebpf_packetOffsetInBits += 32;
			}
		}
        bpf_clone_redirect(ebpf_packet, ebpf_metadata.standard_metadata.egress_port, 0);
    }

    return TC_ACT_SHOT /* drop packet; clone is forwarded */;
}
