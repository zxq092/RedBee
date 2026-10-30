---
name: network-infrastructure
description: Network device and L2 security — SNMP v1/v2c/v3 abuse, LLDP/CDP topology leaks, VLAN hopping, MAC flooding, ARP/NDP spoofing, DHCP starvation/rogue, and default/insecure management interfaces on switches, routers, firewalls and APs.
---

# Network Infrastructure / L2 (网络设备与二层)

Use when the target is a switch, router, firewall, wireless AP/controller, or a segment you
can reach at layer 2. Recon is read-only; the L2 attacks below disrupt the segment, so use
them only on an authorized lab or an isolated VLAN.

## 1. SNMP (usually the fastest route to config/physical map)

- v1/v2c: community strings travel in cleartext; defaults are `public`/`private`/`cisco`/
  `internal`. Brute a small wordlist, then walk the whole tree.
- v3: enumerate users; weak auth (no authNoPriv) and reused credentials are common.
- **Writable community** = configuration changes (system contact/location, sometimes
  running-config via OLD-CISCO-SYSTEM-MIB).

```bash
# no seclists in the sandbox — write a small community list inline
printf 'public\nprivate\ncisco\ninternal\nsnmp\nmanager\nadmin\n' > /tmp/com.txt
onesixtyone -c /tmp/com.txt <target>
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.1            # sysDescr/sysName/uptime
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.2.2.1.2      # ifDescr (interfaces)
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.4.20.1.1     # ipAdEntAddr
snmpwalk -v2c -c public <target> 1.3.6.1.4.1.9.2.1.1      # Cisco running config (OLD-CISCO)
snmpbulkwalk -v3 -u <user> -l noAuthNoPriv <target> 1.3.6.1
snmp-check <target> -c public                             # consolidated view
```

High-value OIDs: `sysDescr`, `sysContact`, `sysLocation`, `ifTable`, `ipAddrTable`,
`ipRouteTable` (routing table), `hrSWRunTable` (processes), vendor config MIBs.

- Writable strings: test with `snmpset -v2c -c private <target> sysContact.0 s test`
  (lab only) — then check for config-dump MIBs.
- The SNMP data gives you the device model/firmware → map to known CVEs and default creds.

## 2. LLDP / CDP topology leak

```bash
lldpcli show neighbors
tcpdump -ni eth0 -c 50 ether proto 0x88cc     # LLDP
tcpdump -ni eth0 -c 50 ether[12:2] = 0x0100   # Cisco CDP (SNAP)
```

Leaks: neighbour hostnames, management IPs, VLAN IDs, port IDs, device models.
This is often enough to draw the topology and find the management network.

## 3. Management interfaces & default credentials

- Ports: 22 ssh, 23 telnet, 80/443 http(s), 161 snmp, 830 netconf, 443 Cisco ASA/ASDM,
  8443, 8080, 4443.
- Default/blank creds per vendor: Cisco (`cisco/cisco`), Juniper (`root`/blank, `netscreen`),
  Huawei (`admin/admin@huawei.com`), MikroTik (`admin`/blank), Fortinet (`admin`/blank),
  APC/UPS/PDU NICs, IPMI (`ADMIN/ADMIN`).
- Check telnet/SSH for banner + auth method; many older devices allow telnet with no ACL.
- Firmware CVE classes: exposed management web UI RCE, SNMP RW abuse, unauth config
  download, SSL VPN appliances. Match the exact firmware version from `sysDescr`.

## 4. VLAN hopping

- **Double tagging (802.1Q-in-Q)**: outer tag = native VLAN, inner tag = victim VLAN; some
  switches forward the frame to the victim VLAN. Works only in specific native-VLAN setups.
- **DTP / switchport negotiation**: if the port negotiates trunking, request a trunk and
  you get all VLANs. `yersinia dtp`.
- Check with `tcpdump -e` for 802.1Q tags (`ether proto 0x8100`) and DTP frames
  (`01:00:0c:cc:cc:cc`).

## 5. MAC flooding / CAM table exhaustion

- Flood the CAM table so the switch fails open (hub mode) → sniff other segments.
  `macof -i eth0` (dsniff) or `yersinia mac`.
- Modern switches have port-security; check for `err-disabled` behaviour.

## 6. ARP / NDP spoofing (MitM on the segment)

```bash
arpspoof -i eth0 -t <victim> <gateway>      # dsniff
bettercap -iface eth0 -eval 'net.probe on; set arp.spoof.targets <victim>; arp.spoof on'
```

- IPv6 equivalent: rogue RA + NDP spoofing (see routing-protocols skill).
- Combine with TLS stripping/DNS spoofing for credentials.

## 7. DHCP starvation / rogue DHCP

- Starve the pool so new clients fail (`yersinia dhcp`, `dhcpstarv`), or run a rogue DHCP
  server handing out your IP as gateway/DNS (MitM). Check for DHCP snooping first.

## 8. Wireless / adjacent (brief)

- Rogue AP with the same SSID (evil twin), open guest VLAN pivoting, WPA-Enterprise
  RADIUS certificate validation gaps. Capture handshakes for offline analysis only when
  authorized.

## Method map

| Goal | Tool |
|---|---|
| SNMP recon/brute | `onesixtyone`, `snmpwalk`, `snmpbulkwalk`, `snmp-check` |
| Topology | `lldpcli`, `tcpdump`/`tshark` |
| L2 attacks | `yersinia`, `macof`, `arpspoof`, `bettercap` |
| Scanning | `nmap -sU -sS`, `arp-scan` |
| DNS/name | `dig`, `nslookup`, `dnsrecon` |

## Reporting

State the device, the protocol/credential used, whether access was read-only or a config
change, and the blast radius (whole VLAN / management network). Never change production
device configuration; demonstrate on lab gear (GNS3/containerlab/EVE-NG or a spare switch).
