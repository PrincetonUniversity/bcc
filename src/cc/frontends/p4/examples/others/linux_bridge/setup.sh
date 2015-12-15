#!/bin/bash

brctl addbr br0
brctl stp br0 off
brctl addif br0 eth1
brctl addif br0 eth3

ip link set dev eth1 up
ip link set dev eth3 up
ip link set dev br0 up
