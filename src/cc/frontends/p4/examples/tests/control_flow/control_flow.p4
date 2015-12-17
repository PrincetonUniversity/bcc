header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

parser start {
    return parse_ethernet;
}

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return ingress;
}

action _nop()
{}

action forward(port)
{
    modify_field(standard_metadata.egress_port, port);
}

action edit()
{
    add_to_field(ethernet.etherType, -1);
}

table tbl1 {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {edit; _nop;}
    size : 512;
}

table tbl2 {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {edit; _nop;}
    size : 512;
}

table tbl3 {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {edit; _nop;}
    size : 512;
}

table tbl4 {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {edit; _nop;}
    size : 512;
}

table tbl5 {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {edit; _nop;}
    size : 512;
}

table tbl6 {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {edit; _nop;}
    size : 512;
}

table tbl7 {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {edit; _nop;}
    size : 512;
}

table tbl8 {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {edit; _nop;}
    size : 512;
}

table tbl9 {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {forward; _nop;}
    size : 512;
}

control ingress
{
    apply(tbl1);
	apply(tbl2);
	apply(tbl3);
	apply(tbl4);
	apply(tbl5);
	apply(tbl6);
	apply(tbl7);
	apply(tbl8);	
	apply(tbl9);	
}
