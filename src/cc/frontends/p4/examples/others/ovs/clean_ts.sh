#!/bin/bash

ip link set dev eth4 down
ip link set dev eth5 down

ovs-vsctl del-br br0
