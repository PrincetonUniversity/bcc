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

action forward(port)
{
    modify_field(standard_metadata.egress_port, port);
}

table fwd {
   reads {
      standard_metadata.ingress_port: exact;
   }
   actions { forward; }
   size : 512;
}

control ingress
{
    apply(fwd);
}