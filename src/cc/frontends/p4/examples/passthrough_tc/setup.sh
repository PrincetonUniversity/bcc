#!/bin/bash

ip link set dev eth1 up
ip link set dev eth3 up

ip link set dev eth1 promisc on
ip link set dev eth3 promisc on

tc qdisc add dev eth1 ingress
tc filter add dev eth1 parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev eth3
tc qdisc add dev eth3 ingress
tc filter add dev eth3 parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev eth1
