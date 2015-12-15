#!/bin/bash

# For this test we will pre-populate ARP caches at the end-hosts

ovs-ofctl del-flows br0

# Verify Checksum (Table 0)
ovs-ofctl add-flow br0 "table=0,priority=32768,dl_type=0x800 \
						                            actions=resubmit(,1)"
ovs-ofctl add-flow br0 "table=0,priority=0 actions="

# IPv4 LPM (Table 1)
ovs-ofctl add-flow br0 "table=1,priority=32768,ip,nw_dst=10.0.0.15/24 \
                                                    actions=set_field:0x0B00000F->reg0, \
                                                            set_field:2->reg1, \
                                                            dec_ttl, \
                                                            resubmit(,2)"
ovs-ofctl add-flow br0 "table=1,priority=0 actions="

# Forward (Table 2)
ovs-ofctl add-flow br0 "table=2,priority=32768,reg0=0x0B00000F \
                                                    actions=set_field:11:11:12:13:14:15->dl_dst, \
                                                            resubmit(,3)"
ovs-ofctl add-flow br0 "table=2,priority=0 actions="

# Send Frame (Table 3)
ovs-ofctl add-flow br0 "table=3,priority=32768,reg1=2 \
                                                    actions=set_field:11:11:12:13:14:14->dl_src, \
                                                            output:NXM_NX_REG1[]"
ovs-ofctl add-flow br0 "table=3,priority=0 actions="

# Setting Hosts
# ip addr add 172.28.129.10/24 dev eth1
# ip route add default via 172.28.129.1 dev eth1
# arp -s 172.28.129.1 08:00:27:13:6c:ef # (Setting permanent ARP entry)
