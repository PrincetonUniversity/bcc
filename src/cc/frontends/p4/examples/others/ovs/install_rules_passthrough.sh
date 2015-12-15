#!/bin/bash

ovs-ofctl del-flows br0
ovs-ofctl add-flow br0 "in_port=1, action=2"
ovs-ofctl add-flow br0 "in_port=2, action=1"