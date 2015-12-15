#!/bin/bash

ovs-vsctl add-br br0
ovs-vsctl add-port br0 eth1
ovs-vsctl add-port br0 eth3

ip link set dev eth1 up
ip link set dev eth3 up