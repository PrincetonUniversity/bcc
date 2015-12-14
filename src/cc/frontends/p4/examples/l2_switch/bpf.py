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
smac_tbl = b.get_table("smac")
smac_miss_tbl = b.get_table("ebpf_smac_miss")
dmac_tbl = b.get_table("dmac")
dmac_miss_tbl = b.get_table("ebpf_dmac_miss")
mcast_src_prun_tbl = b.get_table("mcast_src_pruning")
mcast_src_prun_miss_tbl = b.get_table("ebpf_mcast_src_pruning_miss")


print("Hooking up BPF classifiers using TC")

eth1_idx = ipr.link_lookup(ifname="eth1")[0]
ipr.tc("add", "ingress", eth1_idx, "ffff:")
ipr.tc("add-filter", "bpf", eth1_idx, ":1", fd=fn.fd,
           name=fn.name, parent="ffff:", action="ok", classid=1)

eth3_idx = ipr.link_lookup(ifname="eth3")[0]
ipr.tc("add", "ingress", eth3_idx, "ffff:")
ipr.tc("add-filter", "bpf", eth3_idx, ":1", fd=fn.fd,
           name=fn.name, parent="ffff:", action="ok", classid=1)


class Nop(ctypes.Structure):
    _fields_ = []

class MacLearn(ctypes.Structure):
    _fields_ = []

class SmacUnion(ctypes.Union):
    _fields_ = [("mac_learn", MacLearn),
                ("_nop", Nop)]

class SmacValue(ctypes.Structure):
    _fields_ = [("action", ctypes.c_uint),
                ("u", SmacUnion)]

eth1_smac_val = SmacValue()
eth1_smac_val.action = 1
eth3_smac_val = SmacValue()
eth3_smac_val.action = 1

print("Populating SMAC table from the control plane")
smac_tbl[smac_tbl.Key('\x10\x11\x12\x13\x14\x14')] = eth1_smac_val
smac_tbl[smac_tbl.Key('\x10\x11\x12\x13\x14\x15')] = eth3_smac_val

class Forward(ctypes.Structure):
    _fields_ = [("port", ctypes.c_ushort)]

class Broadcast(ctypes.Structure):
    _fields_ = []

class DmacUnion(ctypes.Union):
    _fields_ = [("forward", Forward),
                ("broadcast", Broadcast)]

class DmacValue(ctypes.Structure):
    _fields_ = [("action", ctypes.c_uint),
                ("u", DmacUnion)]

eth1_dmac_val = DmacValue()
eth1_dmac_val.action = 0
eth1_dmac_val.u.forward.port = eth1_idx

eth3_dmac_val = DmacValue()
eth3_dmac_val.action = 0
eth3_dmac_val.u.forward.port = eth3_idx

print("Populating DMAC table from the control plane")
dmac_tbl[dmac_tbl.Key('\x10\x11\x12\x13\x14\x14')] = eth1_dmac_val
dmac_tbl[dmac_tbl.Key('\x10\x11\x12\x13\x14\x15')] = eth3_dmac_val

class Drop(ctypes.Structure):
    _fields_ = []

class McastSrcPrunUnion(ctypes.Union):
    _fields_ = [("_nop", Nop),
                ("_drop", Drop)]

class McastSrcPrunValue(ctypes.Structure):
    _fields_ = [("action", ctypes.c_uint),
                ("u", McastSrcPrunUnion)]

eth1_mcast_src_prun_val = McastSrcPrunValue()
eth1_mcast_src_prun_val.action = 0
eth3_mcast_src_prun_val = McastSrcPrunValue()
eth3_mcast_src_prun_val.action = 0

print("Populating MAC Src Prunning table from the control plane")
mcast_src_prun_tbl[mcast_src_prun_tbl.Key(eth1_idx)] = eth1_mcast_src_prun_val
mcast_src_prun_tbl[mcast_src_prun_tbl.Key(eth3_idx)] = eth3_mcast_src_prun_val


print("Dumping table contents")
for key, leaf in smac_tbl.items():
    print(str(key.key_field_0), leaf.action)

for key, leaf in dmac_tbl.items():
    print(str(key.key_field_0), leaf.action, leaf.u.forward.port)

for key, leaf in mcast_src_prun_tbl.items():
    print(str(key.key_field_0), leaf.action)
