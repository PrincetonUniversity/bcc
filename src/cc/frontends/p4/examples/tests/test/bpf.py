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
tbl1_tbl = b.get_table("tbl1")
tbl2_tbl = b.get_table("tbl2")
tbl3_tbl = b.get_table("tbl3")
tbl4_tbl = b.get_table("tbl4")
# tbl5_tbl = b.get_table("tbl5")
# tbl6_tbl = b.get_table("tbl6")
# tbl7_tbl = b.get_table("tbl7")
# tbl8_tbl = b.get_table("tbl8")
tbl9_tbl = b.get_table("tbl9")


print("Hooking up BPF classifiers using TC")

eth1_idx = ipr.link_lookup(ifname="eth1")[0]
ipr.tc("add", "ingress", eth1_idx, "ffff:")
ipr.tc("add-filter", "bpf", eth1_idx, ":1", fd=fn.fd,
           name=fn.name, parent="ffff:", action="ok", classid=1)

eth3_idx = ipr.link_lookup(ifname="eth3")[0]
ipr.tc("add", "ingress", eth3_idx, "ffff:")
ipr.tc("add-filter", "bpf", eth3_idx, ":1", fd=fn.fd,
           name=fn.name, parent="ffff:", action="ok", classid=1)

# generating ctypesi
class Nop(ctypes.Structure):
    _fields_ = []

class Drop(ctypes.Structure):
    _fields_ = []

class Edit(ctypes.Structure):
    _fields_ = []

class TblUnion(ctypes.Union):
    _fields_ = [("edit", Edit),
                ("_nop", Nop)]

class TblValue(ctypes.Structure):
    _fields_ = [("action", ctypes.c_uint),
                ("u", TblUnion)]

tbl_val = TblValue()
tbl_val.action = 0

print("Populating tables from the control plane")
tbl1_tbl[tbl1_tbl.Key('\x10\x11\x12\x13\x14\x15')] = tbl_val
tbl2_tbl[tbl2_tbl.Key('\x10\x11\x12\x13\x14\x15')] = tbl_val
tbl3_tbl[tbl3_tbl.Key('\x10\x11\x12\x13\x14\x15')] = tbl_val
tbl4_tbl[tbl4_tbl.Key('\x10\x11\x12\x13\x14\x15')] = tbl_val
# tbl5_tbl[tbl5_tbl.Key('\x10\x11\x12\x13\x14\x15')] = tbl_val
# tbl6_tbl[tbl6_tbl.Key('\x10\x11\x12\x13\x14\x15')] = tbl_val
# tbl7_tbl[tbl7_tbl.Key('\x10\x11\x12\x13\x14\x15')] = tbl_val
# tbl8_tbl[tbl8_tbl.Key('\x10\x11\x12\x13\x14\x15')] = tbl_val

class Forward(ctypes.Structure):
    _fields_ = [("port", ctypes.c_ushort)]

class Tbl9Union(ctypes.Union):
    _fields_ = [("forward", Forward),
                ("_nop", Nop)]

class Tbl9Value(ctypes.Structure):
    _fields_ = [("action", ctypes.c_uint),
                ("u", Tbl9Union)]

# tbl9_eth1_val = Tbl9Value()
# tbl9_eth1_val.action = 0
# tbl9_eth1_val.u.forward.port = eth1_idx

tbl9_eth3_val = Tbl9Value()
tbl9_eth3_val.action = 0
tbl9_eth3_val.u.forward.port = eth3_idx

print("Populating DMAC table from the control plane")
# tbl9_tbl[tbl9_tbl.Key('\x10\x11\x12\x13\x14\x14')] = tbl9_eth1_val
tbl9_tbl[tbl9_tbl.Key('\x10\x11\x12\x13\x14\x15')] = tbl9_eth3_val

print("Dumping table contents")
for key, leaf in tbl1_tbl.items():
    print(str(key.key_field_0), leaf.action)

for key, leaf in tbl9_tbl.items():
    print(str(key.key_field_0), leaf.action, leaf.u.forward.port)
