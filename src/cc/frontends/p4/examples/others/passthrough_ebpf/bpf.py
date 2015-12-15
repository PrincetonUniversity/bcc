#!/usr/bin/env python

from bcc import BPF
from pyroute2 import IPRoute

ipr = IPRoute()

print("Compiling and loading BPF program")
b = BPF(src_file="./bpf.c", debug=0)
fn = b.load_func("ebpf_filter", BPF.SCHED_CLS)
print("BPF program loaded")

# create tc config for interfaces
print("Hooking up BPF classifiers using TC")

eth1_idx = ipr.link_lookup(ifname="eth1")[0]
ipr.tc("add", "ingress", eth1_idx, "ffff:")
ipr.tc("add-filter", "bpf", eth1_idx, ":1", fd=fn.fd,
           name=fn.name, parent="ffff:", action="ok", classid=1)

eth3_idx = ipr.link_lookup(ifname="eth3")[0]
ipr.tc("add", "ingress", eth3_idx, "ffff:")
ipr.tc("add-filter", "bpf", eth3_idx, ":1", fd=fn.fd,
           name=fn.name, parent="ffff:", action="ok", classid=1)
