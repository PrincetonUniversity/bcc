#!/bin/bash

ip link set dev eth4 down
ip link set dev eth5 down
ip link set dev br0 down

brctl delbr br0