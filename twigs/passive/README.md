# twigs passive discovery

`twigs passive` discovers **medical devices, industrial (OT) devices, building
automation systems and IoT devices** by listening to network traffic. It never
sends a packet to the devices it finds, which makes it safe for clinical and
industrial networks where active scans can disrupt infusion pumps, patient
monitors, imaging systems or PLCs.

It analyzes traffic from:

* a **SPAN / mirror port or network TAP** (live capture),
* **pcap files**, or
* **existing Zeek logs** (for sites that already run Zeek / Corelight / Security Onion).

Discovered devices are reported to ThreatWorx as assets, like every other twigs mode.

Contents

1. [What it identifies](#1-what-it-identifies)
2. [How it works](#2-how-it-works)
3. [Requirements and Zeek installation](#3-requirements-and-zeek-installation)
4. [Getting traffic to the sensor: SPAN and TAP](#4-getting-traffic-to-the-sensor-span-and-tap)
5. [Running twigs passive](#5-running-twigs-passive)
6. [Output](#6-output)
7. [Customizing: signatures and asset registry](#7-customizing-signatures-and-asset-registry)
8. [Privacy (PHI)](#8-privacy-phi)
9. [Multiple sensors](#9-multiple-sensors)
10. [Troubleshooting](#10-troubleshooting)
11. [Limitations](#11-limitations)
12. [Development and tests](#12-development-and-tests)

---

## 1. What it identifies

| Category | Examples | Main signals |
|---|---|---|
| **Medical** | infusion pumps (BD Alaris, Baxter, ICU Medical, B. Braun, Fresenius), patient monitors (Philips IntelliVue, GE CARESCAPE, Draeger, Mindray, Spacelabs, Nihon Kohden, Masimo), imaging (CT, MRI, ultrasound, X-ray, mammography from GE, Siemens Healthineers, Philips, Canon, Fujifilm, Agfa, Hologic, Carestream, Shimadzu), PACS, lab and point-of-care analyzers (Sysmex, Abbott, Roche, Radiometer, Cepheid, Beckman Coulter), medication dispensing (Omnicell, Pyxis), nurse call, surgical systems | **DICOM** association (AE titles, implementation UID / version, SOP classes = modality), **HL7** message headers, DHCP vendor class / hostname, HTTP, SNMP, mDNS, NetBIOS, MAC vendor |
| **OT** | PLCs (Rockwell, Siemens, Schneider, Phoenix Contact, WAGO, Beckhoff, OMRON, Mitsubishi), RTUs, protection relays, industrial switches and gateways, HMI / SCADA clients | **EtherNet/IP List Identity**, **Modbus Read Device Identification**, **S7comm**, DNP3, SNMP, MQTT |
| **Building** | BMS controllers (Johnson Controls, Tridium, Honeywell, Automated Logic, Siemens, Schneider, Trane, Carrier), UPS / PDU (APC, Eaton, Vertiv, CyberPower, Raritan), environmental monitors, fire and access control panels | **BACnet** I-Am and ReadProperty (vendor, model, firmware), SNMP, HTTP |
| **IoT** | IP cameras (Axis, Hikvision, Dahua, Hanwha, Bosch, ONVIF), printers, VoIP / conferencing, AV controllers, smart displays | mDNS, SSDP, WS-Discovery, HTTP, MAC vendor |

For every device twigs reports, where available: vendor, model, device class,
firmware / software version, OS (Windows version from NTLM, or a TCP/IP stack
estimate such as VxWorks, QNX, embedded Linux), hostnames, IP and MAC addresses,
protocols in use, and security findings (cleartext DICOM / HL7, Telnet, FTP,
TFTP, VNC, SNMP v1/v2c, end-of-life Windows).

Ordinary workstations, servers and network gear without a medical / OT /
building / IoT signal are not reported.

## 2. How it works

```
 SPAN / TAP ──► Zeek ──► Zeek logs ──► twigs: per-device evidence ──► signatures ──► ThreatWorx assets
  or pcap        │                       (MAC ↔ IP grouping,          (vendor, model,
                 │                        router MAC detection)        class, confidence)
                 ├─ Zeek built-in analyzers: conn, DHCP, DNS/mDNS, HTTP, SNMP, TLS, NTLM, MQTT, DNP3, Modbus
                 ├─ ICSNPP packages (if installed): BACnet, Modbus, EtherNet/IP, S7comm, ...
                 ├─ twigs_passive.zeek: DHCP fingerprint, TCP stack fingerprint, SNMP system strings,
                 │   HTTP Server/User-Agent, mDNS, SSDP, WS-Discovery, NetBIOS, NTLM version, TLS subject
                 └─ twigs DICOM and HL7 parsers (Spicy, compiled automatically on first use)
```

1. **Zeek** turns packets into structured logs. twigs ships its own Zeek scripts
   (`zeek/twigs_passive.zeek`) and two protocol parsers written in Spicy
   (`zeek/medical/dicom.spicy`, `zeek/medical/hl7.spicy`). twigs loads only
   what it needs; it does not use or depend on your site `local.zeek`.
2. **Evidence per device.** Every log record is attributed to the device it
   describes (e.g. the *responder* of an SNMP get, the *sender* of an HL7
   message, the *requester* of a DICOM association). IP addresses are grouped
   into one device by MAC address. MAC addresses seen with many IPs are
   recognised as routers and ignored, so devices in other subnets are reported
   by IP instead of being merged under the router.
3. **Signatures** (`signatures/*.yaml`) match the evidence. Protocols that carry
   identity (EtherNet/IP, Modbus 43/14, BACnet, DICOM) are used directly.
4. **Confidence.** Each matching signal adds a weight; the totals give
   `HIGH` (>= 60), `MEDIUM` (>= 30) or `LOW`. A MAC vendor on its own is `LOW`;
   a DICOM association, a BACnet model name or an SNMP system description is
   enough for `HIGH`.

## 3. Requirements and Zeek installation

| Component | Required for | Notes |
|---|---|---|
| **Zeek 7.0 or later** | everything except `--zeek_logs` | tested with 7.0.9 and 9.0.1 (current LTS) |
| Spicy compiler (`spicyz`) + C++ compiler | DICOM and HL7 identity | included with the Zeek packages below; without it DICOM / HL7 are detected by port only |
| ICSNPP packages | BACnet, Modbus, EtherNet/IP, S7comm identity | installed with `zkg`; without them these protocols are detected by port only |
| IEEE MAC address registry | MAC vendor names | bundled in the twigs Docker image; elsewhere build it (3.3) or twigs falls back to nmap's copy |
| root or `CAP_NET_RAW` | `--interface` | not needed for pcaps or Zeek logs |

### 3.1 Install Zeek on Ubuntu 22.04 / 24.04

Zeek publishes packages through the openSUSE Build Service. `zeek-lts` is the
long-term-support release (recommended).

```bash
. /etc/os-release        # sets VERSION_ID, e.g. 24.04
echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${VERSION_ID}/ /" \
    | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_${VERSION_ID}/Release.key" \
    | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt-get update
sudo apt-get install -y zeek-lts g++ cmake make libpcap-dev git
echo 'export PATH=/opt/zeek/bin:$PATH' | sudo tee /etc/profile.d/zeek.sh
export PATH=/opt/zeek/bin:$PATH
zeek --version
```

Zeek installs into `/opt/zeek`; twigs finds it there automatically, or
anywhere on the `PATH`. The compiler tools are needed to build the DICOM / HL7 parsers
and the ICSNPP packages.

**Ubuntu 20.04:** the Zeek project no longer publishes 20.04 packages. Use an
existing Zeek 7 installation, build Zeek from source
(<https://docs.zeek.org/en/current/install.html>), or run the sensor on Ubuntu
22.04 / 24.04 (a VM or container is fine).

**RHEL / Rocky / Alma, Debian, Fedora:** the same repository has packages for
these distributions; see <https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek-lts>.

### 3.2 Install the ICS protocol packages (ICSNPP)

The [ICSNPP](https://github.com/cisagov/ICSNPP) parsers from CISA add industrial
and building-automation protocols. Install them system-wide with `zkg`, Zeek's
package manager:

```bash
sudo /opt/zeek/bin/zkg autoconfig --force
sudo /opt/zeek/bin/zkg install --force --skiptests \
    icsnpp-bacnet icsnpp-modbus icsnpp-enip icsnpp-s7comm
```

| Package | Adds |
|---|---|
| `icsnpp-bacnet` | BACnet I-Am (vendor, device instance) and ReadProperty values (vendor-name, model-name, firmware-revision) |
| `icsnpp-modbus` | Modbus Read Device Identification (vendor, product code, revision) |
| `icsnpp-enip` | EtherNet/IP / CIP List Identity (vendor, product name, revision, serial number) |
| `icsnpp-s7comm` | Siemens S7comm / S7comm-plus |

Other ICSNPP packages (e.g. `icsnpp-profinet-io-cm`, `icsnpp-opcua-binary`,
`icsnpp-dnp3`) are loaded automatically when installed; their devices are then
classified by protocol. twigs also picks up packages installed per user with
`zkg --user`.

twigs loads every installed package by path. A broken site `local.zeek` (for
example one that loads a package that is not installed) does not affect it.

### 3.3 MAC vendor database

MAC vendor names come from the IEEE registry. The twigs Docker image includes
the current registry (MA-L, MA-M and MA-S) at `/usr/local/share/twigs/oui.txt`,
built when the image is built. On other sensors, build the same file (refresh
it from time to time):

```bash
cd /tmp
for reg in oui/oui.csv oui28/mam.csv oui36/oui36.csv; do
    curl -fsSL -A twigs -O "https://standards-oui.ieee.org/$reg"
done
sudo mkdir -p /usr/local/share/twigs
sudo python3 -m twigs.passive.oui build /usr/local/share/twigs/oui.txt oui.csv mam.csv oui36.csv
```

Without it twigs uses nmap's copy, which can be years out of date (the copy in
nmap on Ubuntu 20.04 is from 2019 and has about half the entries): newer vendor
prefixes are then not recognised. With `-v` twigs logs which database it used
(`MAC vendor database: ...`). `--oui_file` overrides the choice.

### 3.4 First run

The first run compiles the DICOM / HL7 parsers (about a minute) into
`~/.cache/twigs/passive/`. Later runs reuse the compiled parser until twigs or
Zeek is upgraded.

## 4. Getting traffic to the sensor: SPAN and TAP

The sensor is any Linux system (physical, VM or container host) running twigs
and Zeek with a **dedicated capture interface** that receives a copy of the
traffic to monitor. Use a second interface for management and for reporting
to ThreatWorx (HTTPS outbound).

### 4.1 SPAN (port mirroring)

A **SPAN** (Switched Port ANalyzer) or **mirror** session tells a switch to copy
traffic from source ports or VLANs to a destination port where the sensor is
connected.

* No extra hardware; configured on the switch.
* The switch drops mirrored packets when the mirror port is oversubscribed
  (sources add up to more than the destination port speed). Mirror only the
  VLANs you need.
* Copies are lower priority than production traffic, and some switches omit
  malformed frames.

Examples (destination port connected to the sensor's capture interface):

Cisco IOS / IOS-XE:
```
monitor session 1 source vlan 110 , 120 both
monitor session 1 destination interface GigabitEthernet1/0/48
```

Aruba CX:
```
mirror session 1
    source vlan 110 both
    destination interface 1/1/48
    enable
```

Juniper EX (ELS):
```
set forwarding-options analyzer TWIGS input ingress vlan CLINICAL
set forwarding-options analyzer TWIGS input egress vlan CLINICAL
set forwarding-options analyzer TWIGS output interface ge-0/0/47.0
```

To bring traffic from a remote switch to the sensor, use **RSPAN** (a mirror
VLAN carried across trunks) or **ERSPAN** (mirror encapsulated in GRE to the
sensor's IP). Zeek decapsulates GRE tunnels; check with a short test
capture that the mirrored packets are analyzed before relying on ERSPAN.

### 4.2 TAP

A **network TAP** is a passive device placed inline on a link that copies all
packets to monitor ports.

* Sees every packet, including errors, at full line rate; no switch config.
* Requires a brief link interruption to install (or a bypass TAP).
* Most TAPs send each direction on its own monitor port: connect both to the
  sensor, or use an aggregating TAP, or bond the two interfaces in Linux:
  ```
  sudo ip link add tap0 type bond mode balance-rr
  sudo ip link set eth1 master tap0 ; sudo ip link set eth2 master tap0
  sudo ip link set tap0 up
  ```
  and capture on `tap0`.

### 4.3 Where to mirror

Identification depends on seeing the device's own traffic, so place the
mirror close to the devices:

| Network | What to mirror | Why |
|---|---|---|
| Clinical / biomed VLANs | the VLANs of pumps, monitors, analyzers | DHCP, mDNS, NetBIOS and ARP are local broadcasts that never leave the VLAN |
| Imaging | the PACS / modality VLAN, or the PACS uplink | every modality opens DICOM associations to the PACS |
| Interface engine | the link to the HL7 interface engine / LIS | HL7 senders identify themselves in every message |
| Building / facilities | the BMS VLAN and the BMS server uplink | BACnet broadcasts and the BMS polling controllers |
| OT / plant | the controller network, the SCADA / HMI uplink | EtherNet/IP, Modbus and S7 polling carry device identity |
| Core / data center | uplinks of the above (optional) | finds devices by HL7 / DICOM / SNMP / HTTP when VLANs cannot be mirrored; MACs are then the router's (see 9) |

Mirroring a core uplink only works for traffic that crosses it: broadcast
discovery protocols (DHCP, mDNS, NetBIOS, BACnet I-Am) stay in the access VLAN.

### 4.4 Preparing the capture interface

```bash
IF=eth1
sudo ip addr flush dev $IF             # no IP address on the capture port
sudo ip link set dev $IF up promisc on
sudo ethtool -K $IF gro off lro off    # deliver packets as they were on the wire
```

Make it persistent with your distribution's network configuration (netplan,
NetworkManager or systemd-networkd), with no IP address and no default route.

To capture without running twigs as root, give Zeek the capture capabilities:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /opt/zeek/bin/zeek
```

Check that traffic arrives before running discovery:

```bash
sudo tcpdump -ni eth1 -c 20
```

### 4.5 Running in a container

A container has its own network namespace (it cannot see the host's
capture interface) and Docker removes the capture capabilities, so use the
host network and add them back:

```bash
docker run -d --name twigs-passive --restart unless-stopped \
    --net=host --cap-add NET_RAW --cap-add NET_ADMIN \
    -e TW_HANDLE -e TW_TOKEN -e TW_INSTANCE \
    threatworx/twigs -v passive --interface eth1 --continuous --report_interval 1h
```

The twigs image includes Zeek, the ICSNPP packages and the precompiled DICOM /
HL7 parsers. `docker stop` sends SIGTERM, so a final report is sent before the
container exits.

## 5. Running twigs passive

```bash
# Analyze capture files
twigs --handle me@example.com --token XXXX --instance my.threatworx.io \
      passive --pcap ward3.pcap imaging.pcap

# Listen on a SPAN / TAP interface for 4 hours, report once and exit
twigs passive --interface eth1 --duration 4h

# Run as a sensor: listen continuously and report every hour until stopped
twigs passive --interface eth1 --continuous --report_interval 1h

# Analyze logs from an existing Zeek / Corelight sensor
twigs passive --zeek_logs /opt/zeek/logs/current

# Try it without reporting to ThreatWorx: write the assets to a file
twigs --handle me@example.com --out devices.json passive --pcap ward3.pcap
```

| Option | Description |
|---|---|
| `--pcap FILE [FILE ...]` | pcap / pcapng files to analyze |
| `--interface IF` | capture interface connected to a SPAN port or TAP |
| `--zeek_logs DIR [DIR ...]` | existing Zeek logs (JSON or TSV, `.gz` supported) |
| `--duration D` | with `--interface`: listen this long, report once and exit (`300`, `30m`, `4h`, `1d`; default `1h`) |
| `--continuous` | with `--interface`: listen until stopped and report every `--report_interval` (cannot be combined with `--duration` or `--schedule`) |
| `--report_interval I` | with `--continuous`: how often to report (default `1h`, minimum `60s`) |
| `--bpf FILTER` | capture filter, e.g. `"not port 22"` or `"vlan and net 10.10.0.0/16"` |
| `--categories C [C ...]` | report only `medical`, `ot`, `building`, `iot` (default: all) |
| `--min_confidence L` | report only `low` / `medium` / `high` and above (default `low`) |
| `--signatures PATH` | extra signature YAML file or directory (repeatable) |
| `--asset_registry CSV` | known assets (serial numbers, hostnames, MACs), see 7.2 |
| `--oui_file FILE` | MAC vendor database to use instead of the bundled one (twigs, nmap or Wireshark format), see 3.3 |
| `--keep_logs DIR` | keep the Zeek logs for review (default: deleted) |

All global twigs options apply (`--tag`, `--location`, `--org`, `--owner`, `--out`, `--schedule`, `-v`).

### Logs

Use `-v` to see what was found (twigs is silent about results otherwise). The
log goes to the console and to `twigs_passive.log` in the working directory.

* every run / report: `Passive discovery: 31 devices seen, 18 identified (medical 10, ot 3, building 3, iot 2)`
* one line per device: category, confidence, IPs, MAC, vendor, model, device
  class, firmware and what identified it:
  ```
  medical  HIGH  10.10.2.31  00:b0:94:00:20:31  BD  Alaris  Infusion Pump  9.33.1  via DHCP vendor class, hostname, MAC vendor
  ```
* in continuous mode the table is logged only in the final report; each
  interval logs what changed instead:
  ```
  New device: [medical] BD Alaris (Infusion Pump) 10.10.2.31 / 00:b0:94:00:20:31, firmware 9.33.1, confidence HIGH, via DHCP vendor class, hostname, MAC vendor
  Device updated: 10.10.3.20 / 00:10:8d:00:30:20: confidence MEDIUM -> HIGH; firmware - -> 12.0.1.11
  ```
  and `twigs_passive.log` is rotated daily (7 days kept).

`-vv` adds, per device, every matched signature and its score, plus the full
table at each continuous report.

Devices that are quiet in the capture window are not seen. Medical devices
often report only every few minutes; a window of several hours, or continuous
mode, finds far more than a short capture.

### 5.1 Live capture: `--duration` or `--continuous`

Live capture needs packet capture rights: run as root, or give Zeek the
capabilities once (`sudo setcap cap_net_raw,cap_net_admin=eip /opt/zeek/bin/zeek`,
see 4.4) and run twigs as a normal user. This is enforced by the Linux kernel
for every capture tool.

| | `--duration 4h` (default `1h`) | `--continuous` |
|---|---|---|
| Runs | for the duration, then exits | until stopped (Ctrl-C, SIGTERM, `docker stop`, `systemctl stop`) |
| Reports | once, at the end | every `--report_interval`, and a final report when stopped |
| Device knowledge | only what was seen in that window | accumulates for the whole run, so devices that talk rarely are still reported later |
| Repeating | `--schedule "0 */4 * * *" ... --duration 235m` (gaps between runs) | not needed (no gaps) |
| Use for | trials, one-off assessments | permanent sensors |

In continuous mode Zeek runs without interruption and rotates its logs every
few minutes. twigs reads each closed log, adds it to its in-memory device
inventory and deletes it (with `--keep_logs` it is moved to `live/processed/`
instead), so disk use stays flat. If Zeek exits unexpectedly it is restarted
(twigs gives up after 5 restarts within an hour). Every report contains all
devices identified since the start; with `--out` the file is rewritten at each
report.

### 5.2 Running as a service (systemd)

```ini
# /etc/systemd/system/twigs-passive.service
[Unit]
Description=twigs passive discovery sensor
After=network-online.target
Wants=network-online.target

[Service]
Environment=TW_HANDLE=me@example.com
Environment=TW_INSTANCE=my.threatworx.io
# /etc/twigs/token contains one line: TW_TOKEN=...  (chmod 600)
EnvironmentFile=/etc/twigs/token
ExecStart=/usr/local/bin/twigs -v passive --interface eth1 --continuous --report_interval 1h
WorkingDirectory=/var/lib/twigs
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

```bash
sudo mkdir -p /var/lib/twigs /etc/twigs
sudo systemctl daemon-reload
sudo systemctl enable --now twigs-passive
journalctl -u twigs-passive -f
```

The service runs as root by default, which gives Zeek capture rights. twigs
writes its run log (`twigs_passive.log`) to the working directory.

## 6. Output

Each device becomes a twigs asset:

| Field | Value |
|---|---|
| `id` | MAC address when the device is on a mirrored segment, otherwise its IP |
| `name` | DHCP / NetBIOS / SNMP / mDNS hostname, else "vendor device-class (IP)" |
| `type` | `Device` (category, device class and vendor are in the tags) |
| `products` | `vendor model firmware` when the firmware is known, software found in banners (e.g. `dcmtk 3.6.6`), `microsoft windows 6.1` |
| `attack_surface_label` | `Corporate::Network::Device` |
| `config_issues` | cleartext DICOM / HL7, Telnet, FTP, TFTP, VNC, SNMP v1 / v2c, end-of-life Windows |

Tags: `DISCOVERY_TYPE:Passive`, one of `CLINICAL_DEVICE` / `OT_DEVICE` /
`BUILDING_DEVICE` / `IOT_DEVICE`, `CATEGORY:`, `DEVICE_CLASS:`, `VENDOR:`,
`MODEL:`, `FIRMWARE:`, `OS:`, `CONFIDENCE:`, `IP:`, `MAC:`, `PROTOCOL:`, and
`ASSET_TAG:` / `LOCATION:` from the asset registry. The `CLINICAL_DEVICE` and
`OT_DEVICE` tags can be used to keep these devices out of active scans.

## 7. Customizing: signatures and asset registry

### 7.1 Signatures

Built-in signatures are in `signatures/` (`medical.yaml`, `ot.yaml`,
`building.yaml`, `iot.yaml`). Add your own with `--signatures my_rules.yaml`:

```yaml
category: medical          # medical | ot | building | iot (default for the file)
rules:
  - id: acme-infusion
    vendor: Acme Medical
    model: InfuseMaster 3000
    device_class: Infusion Pump
    match:                                  # any field may match; each matching field adds its weight
      dhcp_vendor_class: 'InfuseMaster'
      hostname: '^IM3K-'
      hl7_app: 'InfuseMaster'
    firmware: ['InfuseMaster/([0-9][\w.]+)'] # optional: first capture group is the firmware
```

Patterns are case-insensitive Python regular expressions. Use
`weight_scale: 0.5` to make a broad rule count less.

| Field | Source | Weight |
|---|---|---|
| `snmp_sysdescr`, `snmp_sysobjectid` | SNMP system description / object ID (responses and traps) | 60 |
| `modbus_ident`, `enip` | Modbus device identification, EtherNet/IP identity | 65 |
| `hl7_app` | HL7 MSH-3/MSH-4 of messages the device sent | 65 |
| `dicom_impl` | DICOM implementation class UID and version name | 60 |
| `bacnet` | BACnet vendor, model-name, object-name, firmware | 55 |
| `snmp_trap_enterprise` | SNMP v1 trap enterprise OID | 50 |
| `http_server`, `http_user_agent` | HTTP `Server` / `X-Powered-By`, `User-Agent` | 45 |
| `dhcp_vendor_class` | DHCP option 60 | 40 |
| `tls_subject` | server certificate subject / issuer / SAN | 40 |
| `software` | Zeek software detection (server banners) | 40 |
| `hl7_receiver_app` | HL7 MSH-5/MSH-6 addressed to the device | 40 |
| `s7` | S7comm present | 40 |
| `mdns`, `ssdp`, `wsd`, `mqtt_client_id` | mDNS / DNS-SD, SSDP / UPnP, WS-Discovery, MQTT client ID | 35 |
| `hostname`, `nbns_name`, `snmp_sysname`, `dicom_ae` | any hostname (DHCP, NetBIOS, mDNS, SNMP), NetBIOS name, DICOM AE title | 30 |
| `dhcp_prl` | DHCP option 55 list, e.g. `1,3,6,15` | 25 |
| `mac_vendor` | IEEE OUI organisation name | 20 |

Reference data used by the engine is in `data/`: protocol ports
(`ports.yaml`), DICOM SOP classes and implementation UIDs (`dicom.yaml`) and
TCP stack fingerprints (`tcp_stack.yaml`).

### 7.2 Asset registry

Biomed / clinical engineering usually keeps an inventory with serial numbers
and locations. `--asset_registry` labels matching devices:

```csv
match,vendor,model,device_class,category,location,asset_tag
MQ927EAb9002,Shimadzu,Radspeed Pro,Digital Radiography,medical,Room 1021,BMI-1021
ALARIS-PC-0042,BD,Alaris 8015,Infusion Pump,medical,ICU Bed 4,BME-0042
00:b0:94:12:34:56,BD,Alaris 8015,Infusion Pump,medical,ER,BME-0107
```

`match` is a case-insensitive substring searched for in every identity string
(SNMP descriptions, HTTP banners, DHCP / NetBIOS hostnames, HL7 headers ...),
the MAC address and the IP addresses. Keep customer serial numbers in this
file, not in signatures.

## 8. Privacy (PHI)

Clinical traffic contains protected health information. twigs is built so
that it never stores it:

* **DICOM:** only the association negotiation (A-ASSOCIATE request / accept) is
  parsed: AE titles, implementation UID / version and SOP class UIDs. Image and
  patient data (P-DATA) are skipped unparsed.
* **HL7:** only the MSH (message header) segment is read: sending / receiving
  application and facility, message type, version. PID, OBX and every other
  segment are skipped without being stored.
* SNMP community strings are not stored. Zeek's standard logs (which do contain
  connection metadata such as IPs, URLs and DNS names) are written to a
  temporary directory and deleted after the run unless `--keep_logs` is used.

The automated tests check that the patient fields of the test HL7 messages
never appear in any log.

## 9. Multiple sensors

A sensor only sees the traffic mirrored to it, so larger sites use one sensor
per building, campus or network zone. Each runs `twigs passive` independently
and reports to the same ThreatWorx instance. A few things to plan for:

* **The same device seen by two sensors** (e.g. a modality on the imaging VLAN
  that also sends HL7 across the core) is reported with the same asset ID when
  both see its MAC address, so it becomes one asset. If one sensor sees it only
  behind a router, that sensor reports it by IP; mirror the device's own VLAN
  where possible.
* **Overlapping private address ranges** across sites: devices identified only
  by IP can collide. Run each site with `--location <site>` (and optionally
  `--tag SITE:<site>`), and prefer mirroring access VLANs so devices are
  identified by MAC.
* **Router MACs:** at a routed core every remote device appears with the
  router's MAC. twigs detects MACs used by many IPs and ignores them, so such
  devices are reported by IP.
* **Different coverage per sensor:** broadcast protocols (DHCP, mDNS, NetBIOS,
  BACnet I-Am) are only visible inside their VLAN, so a core sensor identifies
  fewer devices than an access-layer sensor.

## 10. Troubleshooting

| Symptom | Check |
|---|---|
| `Zeek not found` | install Zeek (3.1); twigs looks on the `PATH` and in `/opt/zeek/bin` |
| `No Zeek protocol packages (ICSNPP) found` | install them (3.2) |
| `Failed to compile DICOM / HL7 analyzers` | install `g++` and `cmake`; the message shows the compiler error |
| `Zeek exited early on eth1` / `Zeek stopped unexpectedly` | permissions (run as root or `setcap`, 4.4); interface name; the Zeek output is included in the message |
| no devices from a live capture | `tcpdump -ni <if>` shows traffic? mirror session enabled? capture window long enough? |
| devices identified only by IP | the sensor sees them behind a router; mirror their VLAN (4.3) |
| what matched a device | run with `-vv`; use `--keep_logs` to review the Zeek logs (`twigs_*.log`) |

## 11. Limitations

* **Encrypted traffic** (DICOM over TLS, HTTPS, TLS 1.3 certificates) gives
  only port and TCP-level information.
* **Layer-2 only protocols** (LLDP, CDP, PROFINET DCP, EtherCAT) are not parsed.
* MAC addresses are only available on the same layer-2 segment as the sensor.
* Signatures for vendor-specific behaviour (DHCP vendor classes, hostnames,
  HTTP banners) were built from vendor documentation and synthetic traffic,
  not from customer captures. Expect to tune them during pilots; please
  contribute corrections.
* In continuous mode the device inventory is kept in memory; restarting the
  sensor starts it again from empty (devices reappear as they talk).

## 12. Development and tests

Layout:

```
twigs/passive/
  discovery.py      entry point (twigs passive), options, summary
  zeek_runner.py    finds Zeek / packages, compiles the Spicy parsers, runs Zeek
  zeek_logs.py      reads Zeek JSON / TSV logs
  inventory.py      per-device evidence, MAC / IP grouping, router MAC detection
  classifier.py     signatures, scoring, assets, config issues
  oui.py            MAC vendor lookup
  signatures/       medical.yaml, ot.yaml, building.yaml, iot.yaml
  data/             ports.yaml, dicom.yaml, tcp_stack.yaml
  zeek/             twigs_passive.zeek; medical/ DICOM + HL7 Spicy parsers
  tests/            test_passive.py, make_test_pcaps.py, pcaps/, zeek_logs/
```

Run the tests (the pcap tests are skipped when Zeek is not installed):

```bash
python3 -m unittest twigs.passive.tests.test_passive -v
```

`tests/pcaps/hospital_synthetic.pcap` is a synthetic capture with a CT scanner,
ultrasound and PACS (real DICOM associations generated with pynetdicom), HL7
lab results, an infusion pump and a patient monitor (DHCP), a Stryker system
(HTTP), a medication cabinet (NetBIOS), a BACnet controller, a Modbus PLC with
Telnet open, an SNMP-managed UPS, an IP camera (mDNS / SSDP / WS-Discovery), an
MQTT controller, an ordinary workstation and hosts behind a router. Regenerate
it with `tests/make_test_pcaps.py` (see the script header).
`tests/zeek_logs/` holds Zeek's output for that capture so the classification
tests run without Zeek; refresh it with `--keep_logs` after changing the Zeek
scripts.
