#!/bin/bash

ip link set dev eth4 up
ip link set dev eth5 up

ip link set dev eth4 promisc on
ip link set dev eth5 promisc on

tc qdisc add dev eth4 ingress
tc filter add dev eth4 parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev eth5
tc qdisc add dev eth5 ingress
tc filter add dev eth5 parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev eth4
