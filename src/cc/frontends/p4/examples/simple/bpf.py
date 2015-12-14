#!/usr/bin/env python

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
routing_tbl = b.get_table("routing")
routing_miss_tbl = b.get_table("ebpf_routing_miss")


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
        
class Nop(ctypes.Structure):
    _fields_ = []
            
class Union(ctypes.Union):
    _fields_ = [("nop", Nop),
                ("forward", Forward)]
        
class Value(ctypes.Structure):
    _fields_ = [("action", ctypes.c_uint),
                ("u", Union)]

eth1_val = Value()
eth1_val.action = 1
eth1_val.u.forward.port = eth1_idx
eth3_val = Value()
eth3_val.action = 1
eth3_val.u.forward.port = eth3_idx

print("Populating tables from the control plane")
u_ip = int(IPAddress('10.0.0.14'))
print(u_ip)
routing_tbl[routing_tbl.Key(u_ip)] = eth1_val
u_ip = int(IPAddress('10.0.0.15'))
print(u_ip)
routing_tbl[routing_tbl.Key(u_ip)] = eth3_val


print("Dumping table contents")
for key, leaf in routing_tbl.items():
    print(str(IPAddress(key.key_field_0)), leaf.action, leaf.u.forward.port)

