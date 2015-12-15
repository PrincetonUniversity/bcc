#!/bin/bash

ip link set dev eth1 up
ip link set dev eth3 up

ip link set dev eth1 promisc on
ip link set dev eth3 promisc on

python bpf.py
