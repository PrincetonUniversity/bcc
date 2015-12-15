#!/bin/bash

# p4c-ebpf simple_router.p4 -o bpf.c

ip link set dev eth1 up
ip link set dev eth3 up

ip link set dev eth1 promisc on
ip link set dev eth3 promisc on

python bpf.py
