---
layout: post
title: Configure IPSec PSK RAS on Mikrotik 
category: tips-tricks
tags: [networking, ipsec, mikrotik]
disqus: y
---

The following config has been tested on MikroTik RouterOS 6.48.4 against the following RAS clients:
* Android 11 native VPN client (IPSec PSK)
* macOS Big Sur 11.3 native VPN client

The RAS clients will get an IP in the `10.2.10.0/24` subnet. No split tunnelling.

```mikrotik
/ip ipsec peer
add exchange-mode=ike2 name=peer1 passive=yes send-initial-contact=no
/ip ipsec profile
set [ find default=yes ] dh-group=ecp256,ecp384,modp2048 enc-algorithm=aes-256 hash-algorithm=sha256
/ip ipsec proposal
set [ find default=yes ] auth-algorithms=sha256 enc-algorithms=aes-256-cbc lifetime=1d pfs-group=none
/ip ipsec identity
add generate-policy=port-strict mode-config=vpn peer=peer1 secret=YOURPSKSECRET
/ip pool
add name=vpn-pool ranges=10.2.10.100-10.2.10.150
/ip ipsec mode-config
add address-pool=vpn-pool address-prefix-length=32 name=vpn static-dns=10.2.10.10 system-dns=no
/ip ipsec policy
add dst-address=0.0.0.0/0 src-address=0.0.0.0/0 template=yes
/ip firewall filter
add action=accept chain=input in-interface=ether1-wan port=1701,500,4500 protocol=udp
add action=accept chain=input in-interface=ether1-wan protocol=ipsec-esp
/ip firewall nat
add action=masquerade chain=srcnat out-interface=ether1-wan src-address-list=vpn-lan
```