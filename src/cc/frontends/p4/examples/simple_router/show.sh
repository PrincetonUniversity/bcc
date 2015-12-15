#!/bin/bash

#tc qdisc show

tc filter show dev eth1 parent ffff:
tc filter show dev eth3 parent ffff:

tc -s -d filter show dev eth1 parent ffff:
tc -s -d filter show dev eth3 parent ffff: