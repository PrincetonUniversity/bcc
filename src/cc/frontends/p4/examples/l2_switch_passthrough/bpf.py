#!/usr/bin/env python

import sys
import ctypes
from bcc import BPF
from pyroute2 import IPRoute
from netaddr import IPAddress

ipr = IPRoute()


print("Compiling and loading BPF program")
b = BPF(src_file="./bpf.c", debug=0)
fn = b.load_func("ebpf_filter", BPF.SCHED_CLS)
print("BPF program loaded")


print("Discovering tables")
fwd_tbl = b.get_table("fwd")
fwd_miss_tbl = b.get_table("ebpf_fwd_miss")


print("Hooking up BPF classifiers using TC")

eth1_idx = ipr.link_lookup(ifname="eth1")[0]
ipr.tc("add", "ingress", eth1_idx, "ffff:")
ipr.tc("add-filter", "bpf", eth1_idx, ":1", fd=fn.fd,
           name=fn.name, parent="ffff:", action="ok", classid=1)

eth3_idx = ipr.link_lookup(ifname="eth3")[0]
ipr.tc("add", "ingress", eth3_idx, "ffff:")
ipr.tc("add-filter", "bpf", eth3_idx, ":1", fd=fn.fd,
           name=fn.name, parent="ffff:", action="ok", classid=1)


class Forward(ctypes.Structure):
    _fields_ = [("port", ctypes.c_ushort)]

class FwdUnion(ctypes.Union):
    _fields_ = [("forward", Forward)]

class FwdValue(ctypes.Structure):
    _fields_ = [("action", ctypes.c_uint),
                ("u", FwdUnion)]

eth1_fwd_val = FwdValue()
eth1_fwd_val.action = 0
eth1_fwd_val.u.forward.port = eth3_idx

eth3_fwd_val = FwdValue()
eth3_fwd_val.action = 0
eth3_fwd_val.u.forward.port = eth1_idx

print("Populating Fwd table from the control plane")
fwd_tbl[fwd_tbl.Key(eth1_idx)] = eth1_fwd_val
fwd_tbl[fwd_tbl.Key(eth3_idx)] = eth3_fwd_val


print("Dumping table contents")
for key, leaf in fwd_tbl.items():
    print(str(key.key_field_0), leaf.action, leaf.u.forward.port)
