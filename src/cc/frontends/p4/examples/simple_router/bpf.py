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
ipv4_tbl = b.get_table("ipv4")
ipv4_miss_tbl = b.get_table("ebpf_ipv4_miss")
forward_tbl = b.get_table("forward")
forward_miss_tbl = b.get_table("ebpf_forward_miss")
send_frame_tbl = b.get_table("send_frame")
send_frame_miss_tbl = b.get_table("ebpf_send_frame_miss")


print("Hooking up BPF classifiers using TC")

eth1_idx = ipr.link_lookup(ifname="eth1")[0]
ipr.tc("add", "ingress", eth1_idx, "ffff:")
ipr.tc("add-filter", "bpf", eth1_idx, ":1", fd=fn.fd,
           name=fn.name, parent="ffff:", action="ok", classid=1)

eth3_idx = ipr.link_lookup(ifname="eth3")[0]
ipr.tc("add", "ingress", eth3_idx, "ffff:")
ipr.tc("add-filter", "bpf", eth3_idx, ":1", fd=fn.fd,
           name=fn.name, parent="ffff:", action="ok", classid=1)


class Drop(ctypes.Structure):
    _fields_ = []

class SetNHop(ctypes.Structure):
    _fields_ = [("nhop_ipv4", ctypes.c_uint32),
                ("port", ctypes.c_uint16)]

class IPv4Union(ctypes.Union):
    _fields_ = [("set_nhop", SetNHop),
                ("_drop", Drop)]

class IPv4Value(ctypes.Structure):
    _fields_ = [("action", ctypes.c_uint32),
                ("u", IPv4Union)]

eth1_ipv4_val = IPv4Value()
eth1_ipv4_val.action = 0
eth1_ipv4_val.u.set_nhop.nhop_ipv4 = int(IPAddress('11.0.0.14'))
eth1_ipv4_val.u.set_nhop.port = eth1_idx

eth3_ipv4_val = IPv4Value()
eth3_ipv4_val.action = 0
eth3_ipv4_val.u.set_nhop.nhop_ipv4 = int(IPAddress('11.0.0.15'))
eth3_ipv4_val.u.set_nhop.port = eth3_idx

print("Populating IPv4 table from the control plane")
ipv4_tbl[ipv4_tbl.Key(int(IPAddress('10.0.0.14')))] = eth1_ipv4_val
ipv4_tbl[ipv4_tbl.Key(int(IPAddress('10.0.0.15')))] = eth3_ipv4_val


class SetDMAC(ctypes.Structure):
    _fields_ = [("dmac", ctypes.c_ubyte * 6)]

class ForwardUnion(ctypes.Union):
    _fields_ = [("set_dmac", SetDMAC),
                ("_drop", Drop)]

class ForwardValue(ctypes.Structure):
    _fields_ = [("action", ctypes.c_uint32),
                ("u", ForwardUnion)]

eth1_fwd_val = ForwardValue()
eth1_fwd_val.action = 0
eth1_fwd_val.u.set_dmac.dmac = (ctypes.c_ubyte * 6)(0x10,0x11,0x12,0x13,0x14,0x14);

eth3_fwd_val = ForwardValue()
eth3_fwd_val.action = 0
eth3_fwd_val.u.set_dmac.dmac = (ctypes.c_ubyte * 6)(0x10,0x11,0x12,0x13,0x14,0x15);

print("Populating Forward table from the control plane")
forward_tbl[forward_tbl.Key(int(IPAddress('11.0.0.14')))] = eth1_fwd_val
forward_tbl[forward_tbl.Key(int(IPAddress('11.0.0.15')))] = eth3_fwd_val


class RewriteMAC(ctypes.Structure):
    _fields_ = [("smac", ctypes.c_ubyte * 6)]

class SendFrameUnion(ctypes.Union):
    _fields_ = [("rewrite_mac", RewriteMAC),
                ("_drop", Drop)]

class SendFrameValue(ctypes.Structure):
    _fields_ = [("action", ctypes.c_uint32),
                ("u", SendFrameUnion)]

eth1_snd_val = SendFrameValue()
eth1_snd_val.action = 0
eth1_snd_val.u.rewrite_mac.smac = (ctypes.c_ubyte * 6)(0x10,0x11,0x12,0x13,0x14,0x15);

eth3_snd_val = SendFrameValue()
eth3_snd_val.action = 0
eth3_snd_val.u.rewrite_mac.smac = (ctypes.c_ubyte * 6)(0x10,0x11,0x12,0x13,0x14,0x14);

print("Populating Send Frame table from the control plane")
send_frame_tbl[send_frame_tbl.Key(eth1_idx)] = eth1_snd_val
send_frame_tbl[send_frame_tbl.Key(eth3_idx)] = eth3_snd_val


print("Dumping table contents")
for key, leaf in ipv4_tbl.items():
    print(str(key.key_field_0), leaf.action, leaf.u.set_nhop.nhop_ipv4, leaf.u.set_nhop.port)

for key, leaf in forward_tbl.items():
    print(str(key.key_field_0), leaf.action, leaf.u.set_dmac.dmac)

for key, leaf in send_frame_tbl.items():
    print(str(key.key_field_0), leaf.action, leaf.u.rewrite_mac.smac)

