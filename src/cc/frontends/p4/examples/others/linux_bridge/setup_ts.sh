#!/bin/bash

brctl addbr br0
brctl stp br0 off
brctl addif br0 eth4
brctl addif br0 eth5

ip link set dev eth4 up
ip link set dev eth5 up
ip link set dev br0 up
