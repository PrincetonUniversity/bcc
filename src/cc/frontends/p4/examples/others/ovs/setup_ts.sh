#!/bin/bash

ovs-vsctl add-br br0
ovs-vsctl add-port br0 eth4
ovs-vsctl add-port br0 eth5

ip link set dev eth4 up
ip link set dev eth5 up