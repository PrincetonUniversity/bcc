#!/bin/bash

tc qdisc del dev eth4 ingress
tc qdisc del dev eth5 ingress

ip link set dev eth4 promisc off
ip link set dev eth5 promisc off

ip link set dev eth4 down
ip link set dev eth5 down

