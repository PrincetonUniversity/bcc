#!/bin/bash

# p4c-ebpf l2_switch.p4 -o bpf_ts.c

ip link set dev eth4 up
ip link set dev eth5 up

ip link set dev eth4 promisc on
ip link set dev eth5 promisc on

python bpf_ts.py
