---
name: ot-ics-security
description: OT/ICS and critical-infrastructure (电力/工控) assessment — fingerprint PLC/RTU/HMI, then test unauthenticated industrial protocols (Modbus, DNP3, IEC 104, S7comm, EtherNet/IP, OPC UA, BACnet) for read/write abuse.
---

# OT / ICS Security (电力 / 工控 / SCADA)

Use when the target is a control system, PLC, RTU, HMI, engineering workstation, or an
industrial protocol port — not a normal web app. Start **read-only** (identity + status
registers) and only attempt writes on an authorized lab target: writing a coil or
stopping a CPU can physically disrupt equipment.

## 1. Discovery & fingerprinting

Common industrial ports:

| Port | Protocol | Typical device |
|---|---|---|
| 502/tcp | Modbus/TCP | PLC, RTU, gateway |
| 102/tcp | S7comm (ISO-TSAP) | Siemens S7-300/400/1200/1500 |
| 20000/tcp | DNP3 | RTU / utility |
| 2404/tcp | IEC 60870-5-104 | power-grid RTU/gateway |
| 44818/tcp | EtherNet/IP + CIP | Rockwell/Allen-Bradley |
| 47808/udp | BACnet | building automation (HVAC) |
| 4840/tcp | OPC UA | SCADA server / HMI |
| 1911,4911/tcp | Tridium Niagara Fox | BMS/HVAC |
| 9600/tcp | OMRON FINS | OMRON PLC |
| 5007/tcp | MELSEC (Mitsubishi) | Mitsubishi PLC |
| 789/tcp | PCWorx | Phoenix Contact |

Nmap NSE scripts (already installed in the sandbox) identify vendor/model without login:

```bash
nmap -Pn -p 502,102,20000,2404,44818,47808,4840,1911 --script modbus-discover,s7-info,enip-info,iec-identify,stuxnet-detect -sV <target>
nmap -Pn -sU -p 47808,161 --script bacnet-info,snmp-info <target>
```

Banner-less services: confirm with a raw connect + one well-formed request (see below).
Note **unit-id / destination-address** scanning — many gateways expose several slaves.

## 2. Modbus/TCP (no authentication by design)

Function codes: 1 read coils, 2 read discrete inputs, 3 read holding registers,
4 read input registers, 5 write single coil, 6 write single register,
15 write multiple coils, 16 write multiple registers, 23 read/write multiple.

```python
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient("<target>", port=502); assert c.connect()
print(c.read_holding_registers(0, count=20, device_id=1))   # identity / setpoints
print(c.read_coils(0, count=16, device_id=1))               # outputs / actuators
# sequential ASCII string in holding registers (typical "flag" / serial / password):
r = c.read_holding_registers(100, count=40, device_id=1)
print("".join(chr(x) for x in r.registers if 32 <= x < 127))
# write ONLY on an authorized lab target:
# c.write_register(0, 1, device_id=1)
c.close()
```

**Run this with the container-side `python`/`terminal` tool** — the `bash` tool executes
on the host, which has no `pymodbus`.

API notes (pymodbus 3.16.1, verified in the sandbox image):
- the unit-id keyword is `device_id=`; `slave=` is **gone** and raises `TypeError`.
- client reads are keyword-only: `read_holding_registers(addr, count=N, device_id=N)`.
- building a local fake PLC has an off-by-one bug:
  `ModbusSequentialDataBlock(0, values)` raises `TypeError: 0 <= address < 65535`
  → always pass **`1`** as the address (`ModbusSequentialDataBlock(1, values)`).

Sweep unit ids (1..247) and register ranges; look for device-name/version registers,
setpoints, and coil patterns that map to physical outputs. ASCII stored one character
per register is the most common way a "flag"/serial is hidden in a PLC.

## 3. DNP3 (legacy deployments often have no secure-authentication)

- Integrity poll (function 1/2) dumps all points without credentials.
- Control operations (CROB, function 4/5) can trip breakers / open valves —
  treat as write operations, lab only.
- Frames are unencrypted and the link layer has no auth unless DNP3-SA is configured.
- Tooling: `scapy` `Raw` frames (build the 0x0564 link header + transport + APDU by hand),
  or an external `opendnp3`/`pydnp3` install (not in the sandbox by default).

## 4. IEC 60870-5-104 (power grid telecontrol)

- TCP 2404. Send `STARTDT act` (U-frame) to open the data transfer, then read
  interrogation ASDU (`C_IC_NA_1`, type 100) to enumerate measurement points.
- Single command `C_SC_NA_1` (type 45), setpoint `C_SE_NC_1` (type 50) = control writes.
- Craft APDUs directly with `socket` + `struct` (start byte `0x68`, length, 4 control
  bytes, ASDU); `pyiec104` is installable but its py3.14 wheel is broken (empty package),
  so prefer raw frames.

## 5. S7comm (Siemens)

```bash
# snap7 (python-snap7) — version, read DB, and (lab only) stop/start CPU
python3 - <<'PY'
import snap7
c = snap7.client.Client(); c.connect("<target>", 0, 1)
print(c.get_cpu_info()); print(c.get_cpu_state())
print(c.db_read(1, 0, 64))        # DB1 first 64 bytes
# c.plc_stop()  # disruptive — authorized lab only
PY
```

S7-300/400 with protection disabled allow CPU stop/start and program download.

## 6. EtherNet/IP / CIP, BACnet, OPC UA

- EtherNet/IP: `enip-info` NSE, then CIP list-identity / list-tags (unauthenticated on
  many PLCs). Tags often map to process variables.
- BACnet (47808/udp): `bacnet-info`, then `Who-Is` / `ReadProperty` — building HVAC
  setpoints, schedules, and sometimes credentials in device objects.
- OPC UA (4840): enumerate endpoints, try an anonymous session; check for
  `SecurityPolicy: None` endpoints and anonymous user tokens.

```python
from asyncua import Client
# endpoints = await Client("<target>").connect() ... browse the address space
```

## 7. HMI / engineering workstation (the human layer)

- HMI web panels and VNC/RDP with default or blank credentials.
- Project/config files on shares (`*.scd`, `*.ap16`, `*.dwg`, `*.s7p`) leak topology.
- Windows engineering hosts: check for stored PLC credentials in project files
  and for older S7/RSLogix versions with known RCE.

## Reporting (critical)

For OT findings, always state: protocol, port, whether the operation was **read-only or a
write**, the register/object touched, and the **physical consequence** (e.g. "holding
register 0 controls pump speed"). Do not perform writes on a production device.

## Safety / scope

- Default to read-only (function 1-4, identity, interrogation).
- Never write coils/registers, stop a CPU, or change setpoints outside an authorized lab.
- Change of state in OT can be safety-critical: document before/after, and prefer a
  simulated target (`Conpot`, `pymodbus` server) for demonstrations.
