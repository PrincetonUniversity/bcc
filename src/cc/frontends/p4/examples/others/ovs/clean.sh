#!/bin/bash

ip link set dev eth1 down
ip link set dev eth3 down

ovs-vsctl del-br br0
