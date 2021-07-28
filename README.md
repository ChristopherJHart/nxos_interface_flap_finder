# NX-OS Interface Flap Finder

This script connects to one or more Cisco Nexus switches running NX-OS software, identifies interfaces that have flapped more than a certain amount, and generates a report indicating which switches and interfaces have flapped the most.

```
$ python nxos_interface_flap_finder.py 192.0.2.10 192.0.2.20 --interface-flap-floor 1
Input password for user account admin: 
+----------------+---------------+-------------+-----------------+
| IP             | Hostname      | Interface   | Number of Flaps |
+----------------+---------------+-------------+-----------------+
| 192.0.2.10     | N5K-C56128P-1 | Ethernet1/3 |        2        |
| 192.0.2.20     | N5K-C56128P-2 | Ethernet1/1 |        1        |
| 192.0.2.20     | N5K-C56128P-2 | Ethernet1/3 |        1        |
| 192.0.2.20     | N5K-C56128P-2 | Ethernet1/5 |        1        |
+----------------+---------------+-------------+-----------------+
```

This script can be used as a stop-gap measure in place of a more comprehensive syslog aggregation solution. Long-term, users should consider implementing a more robust syslog solution, such as ELK (Elasticsearch, Logstash, and Kibana), Graylog, or Splunk.

## Usage

This script can be used as shown below:

```
python nxos_interface_flap_finder.py <switch-1-ip-address-or-fqdn> [switch-2-ip-address-or-fqdn] ... [switch-n-ip-address-or-fqdn] [--username switch-username] [--password switch-password] [--interface-flap-floor 5] [--connect-only]
```

Required parameters include:

* **switch-ip-address-or-fqdn** - The IP address or Fully Qualified Domain Name (FQDN) of the Cisco Nexus switch(es) that you would like to analyze. One or more IP addresses or FQDNs (or a mixture) can be used.

Optional parameters include:

* **--username** - The username that should be used to access each Cisco Nexus switch. Note that the same username will be used to access all specified switches. A unique username per switch is not supported. If no username is defined, the default username of "admin" will be used.
* **--password** - The password that should be used to access each Cisco Nexus switch. Note that the same password will be used to access all specified switches. A unique password per switch is not supported. If no password is defined, the script will prompt you to input the password immediately after execution.
* **--interface-flap-floor** - An integer representing the minimum number of flaps that an interface must encounter in order to be reported. If a floor is not defined, a default integer of 5 is used.
* **--connect-only** - Connects to all defined switches, but does not analyze each switch's syslog or generate an interface flap report. Useful for verifying that the script has accessibility to all defined switches before generating a report.
* **--include-metadata** - Add metadata for each switch with an applicable quantity of interface flaps to the interface flap report generated by the script.
* **--verbose** - Increases the verbosity of logging. Informational logs are displayed in the script's output alongside the interface flap report.
* **--debug** - Increases the verbosity of logging. Debug logs are displayed in the script's output alongside the interface flap report.

## Installation

This script can be installed using the instructions below:

1. Clone this repository to your workstation of choice.

```shell
git clone https://github.com/ChristopherJHart/nxos_interface_flap_finder.git
```

2. Move into the newly-created directory.

```shell
cd nxos_interface_flap_finder
```

3. Create and activate a virtual environment to house the script's dependencies.

```shell
python -m venv venv; source venv/bin/activate
```

4. Install the script's dependencies using `pip`:

```shell
pip install -r requirements.txt
```

5. Execute the script. The example below identifies all interfaces that have flapped one or more times on two Cisco Nexus switches reachable at 192.0.2.10 and 192.0.2.20, respectively.

```shell
python nxos_interface_flap_finder.py 192.0.2.10 192.0.2.20 --interface-flap-floor 1
```

## FAQ

### What does "flap" mean?

In the context of network operations, a "flap" is when a network entity is in a working status, transitions to a non-working status, then transitions to a working status shortly afterwards. The word "bounce" is also sometimes used in place of the word "flap". Both words can be used to describe control plane protocol status, interface status, module or network device status, and so on. For example:

> "The OSPF adjacency between the two routers was continuously **flapping**, causing instability in the network as IPv4 prefixes were rapidly inserted and removed from unicast routing tables."

> "One of the DWDM service provider's optical devices encountered hardware failure, degrading the signal in the circuit and causing the interface of our switch to **flap**. This disrupted network connectivity between sites."

### How do you measure a flap?

This script associates interface flaps with the "interface resets" counter present in a Nexus switch's interface statistics. An example of this can be found in the `show interface` command, as shown below.

```
switch# show interface
<snip>
Ethernet1/1 is up
 Dedicated Interface 

  Hardware: 1000/10000 Ethernet, address: 00de.fb61.4468 (bia 00de.fb61.4468)
  MTU 1500 bytes,  BW 10000000 Kbit, DLY 10 usec
  reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, medium is broadcast
  Port mode is access
  full-duplex, 10 Gb/s, media type is 10G
  Beacon is turned off
  Input flow-control is off, output flow-control is off
  Rate mode is dedicated
  Switchport monitor is off 
  EtherType is 0x8100 
  Last link flapped 05:46:22
  Last clearing of "show interface" counters never
  1 interface resets    <<<
  30 seconds input rate 344 bits/sec, 0 packets/sec
  30 seconds output rate 72 bits/sec, 0 packets/sec
  Load-Interval #2: 5 minute (300 seconds)
    input rate 200 bps, 0 pps; output rate 136 bps, 0 pps
  RX
    0 unicast packets  11444 multicast packets  0 broadcast packets
    11444 input packets  1031554 bytes
    0 jumbo packets  0 storm suppression bytes
    0 runts  0 giants  0 CRC  0 no buffer
    0 input error  0 short frame  0 overrun   0 underrun  0 ignored
    0 watchdog  0 bad etype drop  0 bad proto drop  0 if down drop
    0 input with dribble  0 input discard
    0 Rx pause
  TX
    0 unicast packets  1055 multicast packets  0 broadcast packets
    1055 output packets  364652 bytes
    0 jumbo packets
    0 output error  0 collision  0 deferred  0 late collision
    0 lost carrier  0 no carrier  0 babble 0 output discard
    0 Tx pause
```

Every network environment is different. Some networks may expect hundreds or thousands of flaps on a regular basis on specific interfaces. For this reason, the `--interface-flap-floor` parameter can be used with this script to fine-tune the threshold between normal behavior and abnormal flapping behavior. The default value for this parameter is 5.
