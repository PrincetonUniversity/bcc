#!/usr/bin/env python

from bcc import BPF
from pyroute2 import IPRoute

ipr = IPRoute()

print("Compiling and loading BPF program")
b = BPF(src_file="./bpf_ts.c", debug=0)
fn = b.load_func("ebpf_filter", BPF.SCHED_CLS)
print("BPF program loaded")

# create tc config for interfaces
print("Hooking up BPF classifiers using TC")

eth4_idx = ipr.link_lookup(ifname="eth4")[0]
ipr.tc("add", "ingress", eth4_idx, "ffff:")
ipr.tc("add-filter", "bpf", eth4_idx, ":1", fd=fn.fd,
           name=fn.name, parent="ffff:", action="ok", classid=1)

eth5_idx = ipr.link_lookup(ifname="eth5")[0]
ipr.tc("add", "ingress", eth5_idx, "ffff:")
ipr.tc("add-filter", "bpf", eth5_idx, ":1", fd=fn.fd,
           name=fn.name, parent="ffff:", action="ok", classid=1)
