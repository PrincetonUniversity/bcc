#!/bin/bash

ip link set dev eth4 up
ip link set dev eth5 up

ip link set dev eth4 promisc on
ip link set dev eth5 promisc on

python bpf_ts.py
