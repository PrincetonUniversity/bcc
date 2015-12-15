#!/bin/bash

ovs-ofctl del-flows br0

# SMAC Table 0
ovs-ofctl add-flow br0 "table=0,priority=32768,dl_src=10:11:12:13:14:14 actions=resubmit(,1)"
ovs-ofctl add-flow br0 "table=0,priority=0                           actions=controller"

# DMAC Table 1
ovs-ofctl add-flow br0 "table=1,priority=32768,dl_dst=10:11:12:13:14:15 actions=set_field:2->reg0,resubmit(,2)"
ovs-ofctl add-flow br0 "table=1,priority=0                           actions=flood"

# SRC Pruning Table 2
ovs-ofctl add-flow br0 "table=2,priority=32768,in_port=1,reg0=1 actions="
ovs-ofctl add-flow br0 "table=2,priority=32768,in_port=2,reg0=2 actions="
ovs-ofctl add-flow br0 "table=2,priority=32768,in_port=3,reg0=3 actions="
ovs-ofctl add-flow br0 "table=2,priority=32768,in_port=4,reg0=4 actions="
ovs-ofctl add-flow br0 "table=2,priority=32768,in_port=5,reg0=5 actions="
ovs-ofctl add-flow br0 "table=2,priority=32768,in_port=6,reg0=6 actions="
ovs-ofctl add-flow br0 "table=2,priority=0                      actions=output:NXM_NX_REG0[]"
