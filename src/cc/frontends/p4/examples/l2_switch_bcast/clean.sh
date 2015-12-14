#!/bin/bash

tc qdisc del dev eth1 ingress
tc qdisc del dev eth3 ingress

ip link set dev eth1 promisc off
ip link set dev eth3 promisc off
ip link set dev eth4 promisc off
ip link set dev eth5 promisc off
ip link set dev eth6 promisc off
ip link set dev eth7 promisc off

ip link set dev eth1 down
ip link set dev eth3 down
ip link set dev eth4 down
ip link set dev eth5 down
ip link set dev eth6 down
ip link set dev eth7 down

rm -rf bpf.c