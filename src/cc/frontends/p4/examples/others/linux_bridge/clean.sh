#!/bin/bash

ip link set dev eth1 down
ip link set dev eth3 down
ip link set dev br0 down

brctl delbr br0