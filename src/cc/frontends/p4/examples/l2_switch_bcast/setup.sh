#!/bin/bash

p4c-ebpf l2_switch.p4 -o bpf.c

ip link set dev eth1 up
ip link set dev eth3 up
ip link set dev eth4 up
ip link set dev eth5 up
ip link set dev eth6 up
ip link set dev eth7 up

ip link set dev eth1 promisc on
ip link set dev eth3 promisc on
ip link set dev eth4 promisc on
ip link set dev eth5 promisc on
ip link set dev eth6 promisc on
ip link set dev eth7 promisc on

python bpf.py
