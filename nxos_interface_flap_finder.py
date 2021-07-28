#!/usr/bin/env python
"""Identifies and reports regularly-flapping interfaces on multiple Nexus switches."""

from typing import List, Union
import time
import argparse
import logging
import sys
import asyncio
import re
from getpass import getpass
from scrapli.driver.core.cisco_nxos import AsyncNXOSDriver
from scrapli.exceptions import ScrapliAuthenticationFailed
from prettytable import PrettyTable


__author__ = "Christopher Hart"
__email__ = "chart2@cisco.com"
__copyright__ = "Copyright (c) 2021 Cisco Systems. All rights reserved."
__credits__ = [
    "Christopher Hart",
]
__license__ = """
################################################################################
# Copyright (c) 2021 Cisco and/or its affiliates.
#
# This software is licensed to you under the terms of the Cisco Sample
# Code License, Version 1.1 (the "License"). You may obtain a copy of the
# License at
#
#                https://developer.cisco.com/docs/licenses
#
# All use of the material herein must be in accordance with the terms of
# the License. All rights not expressly granted by the License are
# reserved. Unless required by applicable law or agreed to separately in
# writing, software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied.
################################################################################
"""

INTERFACE_NAME_PATTERN = re.compile(r"^(?P<interface>\S+)\s+is\s+")
INTERFACE_RESET_PATTERN = re.compile(r"^\s+(?P<flaps>\d+)\s+interface\s+resets")


parser = argparse.ArgumentParser(
    description=(
        "Connects to multiple Nexus switches and identifies regularly-flapping interfaces, then "
        "ranks them from highest to lowest."
    )
)

# Required argument
parser.add_argument(
    "switch_information",
    metavar="ip/fqdn",
    help="IP or FQDN of switches to analyze.",
    nargs="+",
)

# Optional arguments
parser.add_argument("--debug", "-d", help="Enable debug logging", action="store_true")
parser.add_argument(
    "--verbose", "-v", help="Increase verbosity of logging", action="store_true"
)
parser.add_argument(
    "--username",
    "-u",
    metavar="admin",
    help="Username to log into each Nexus switch with.",
    action="store",
    default="admin",
)
parser.add_argument(
    "--password",
    "-p",
    metavar="cisco!123",
    help="Password to log into each Nexus switch with.",
    action="store",
)
parser.add_argument(
    "--interface-flap-floor",
    "-f",
    metavar=5,
    help="Minimum quantity of interface flaps to be considered significant.",
    action="store",
    type=int,
    default=5,
)
parser.add_argument(
    "--connect-only",
    "-c",
    help="Only connect to devices, do not execute commands.",
    action="store_true",
    default=False,
)
parser.add_argument(
    "--include-metadata",
    "-m",
    help="Add switch metadata to output.",
    action="store_true",
    default=False,
)

args = parser.parse_args()

if args.debug:
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG,
        format="%(asctime)-15s %(levelname)-8s [%(funcName)20s] %(message)s",
    )
elif args.verbose:
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.INFO,
        format="%(asctime)-15s %(levelname)-8s [%(funcName)20s] %(message)s",
    )
    logging.getLogger("scrapli").setLevel(logging.WARNING)
    logging.getLogger("asyncssh").setLevel(logging.WARNING)
else:
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.WARNING,
        format="%(asctime)-15s %(levelname)-8s [%(funcName)20s] %(message)s",
    )
    logging.getLogger("scrapli").setLevel(logging.WARNING)
    logging.getLogger("asyncssh").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


async def connect_to_device(host: str, username: str, password: str) -> AsyncNXOSDriver:
    """Open an SSH connection to a specific device.

    Args:
        host (str): IP or FQDN or switch to connect to via SSH.
        username (str): Username of user account to use when connecting to switch.
        password (str): Password of user account to use when connecting to switch.

    Returns:
        AsyncNXOSDriver: Scrapli driver representing the SSH connection to the switch.
    """
    logger.debug("Connecting to device %s with username %s", host, username)
    conn = AsyncNXOSDriver(
        transport="asyncssh",
        host=host,
        auth_username=username,
        auth_password=password,
        auth_strict_key=False,
    )
    try:
        await conn.open()
    except ScrapliAuthenticationFailed:
        logger.warning(
            "Failed to connect to device %s with username %s. Please validate that you can "
            "manually SSH into the switch using this same information and that this switch is "
            "reachable.",
            host,
            username,
        )
        return conn
    prompt = await conn.get_prompt()
    logger.info("Connected to device %s (%s)", prompt.replace("#", ""), host)
    return conn


async def validate_connections(
    switch_information: List[str], username: str, password: str
) -> List[AsyncNXOSDriver]:
    """Verify whether all switches are reachable via SSH.

    Args:
        switch_information (List[str]): List of strings representing the IP or FQDN of each switch
            we should validate connectivity to.
        username (str): Username of user account to use when connecting to each switch.
        password (str): Password of user account to use when connecting to each switch.

    Returns:
        List[AsyncNXOSDriver]: List of Scrapli drivers, each representing an SSH connection to each
            switch.
    """
    logger.info("Validating connectivity to %s devices", len(switch_information))
    connections = await asyncio.gather(
        *[connect_to_device(ip, username, password) for ip in switch_information]
    )
    if failed_connections := [c for c in connections if not c.isalive()]:
        print(
            f"Failed to connect to the following devices with a username of {username}:"
        )
        print()
        for failed_connection in failed_connections:
            print(failed_connection.host)
        print()
        print(
            "Please validate that you can manually SSH into these switches using the same "
            "information provided to this script."
        )
        return
    logger.info("Connected to %s devices successfully", len(connections))
    return connections


async def command(
    conn: AsyncNXOSDriver, command: str, structured: bool = False
) -> Union[str, dict]:
    """Get normal or TextFSM structured output of show command from switch.

    Args:
        conn (AsyncNXOSDriver): Scrapli driver representing the connection to the Nexus switch.
        command (str): Command to execute on switch.
        structured (bool): Indicates whether TextFSM structured output of command should be
            returned switch or not.

    Returns:
        Union[str, dict]: The output of `command` executed on the switch using `conn`. If
        `structured` is True, then TextFSM structured output of the command is returned. If
        `structured` is False, then the raw string output of the command is returned.
    """
    response = await conn.send_command(command)
    response.raise_for_status()
    if structured:
        return response.textfsm_parse_output()
    return response.result


async def analyze_interfaces_for_flaps(interface_data: str) -> List[dict]:
    """Analyze interface information for flaps.

    Iterates through the output of "show interface" from a Nexus switch and identifies interface
    reset counters that indicate an interface has flapped. An example of this is shown below:

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

    Args:
        interface_data (str): The output of "show interface" from a Nexus switch.

    Returns:
        List[dict]: List of dictionaries representing flapped interfaces on this switch. Sample
        output is as follows:

        [
            {"Ethernet1/1": 1},
            {"Ethernet1/2": 5},
            {"Ethernet1/3": 8}
        ]
    """
    interfaces = {}
    current_interface = None
    for line in interface_data.splitlines():
        if name_res := INTERFACE_NAME_PATTERN.search(line):
            current_interface = name_res.groupdict()["interface"]
            logger.debug("Found interface %s", current_interface)
        if reset_res := INTERFACE_RESET_PATTERN.search(line):
            flaps = int(reset_res.groupdict()["flaps"])
            logger.debug("Found flaps %s for interface %s", flaps, current_interface)
            interfaces[current_interface] = flaps
            current_interface = None
    return interfaces


async def get_interface_flaps(conn: AsyncNXOSDriver) -> List[dict]:
    """Identify interface flaps on a switch.

    Fetches the output of "show logging logfile" from a Nexus switch and passes it into
    analyze_syslog_for_interface_flaps() for analysis. The results from this coroutine are modified
    such that the switch's IP and switchname (per CLI prompt) are associated with each interface and
    its quantity of flaps.

    Args:
        conn (AsyncNXOSDriver): Scrapli driver representing the connection to the Nexus switch.

    Returns:
        List[dict]: List of dictionaries representing each unique (device, interface, number of
        flaps) tuple. Sample output if the "--include-metadata" parameter is not provided is as
        follows:

        [
            {"ip": "192.0.2.10", "switchname": "N9K-1", "interface": "Ethernet1/1", "flaps": 1},
            {"ip": "192.0.2.10", "switchname": "N9K-1", "interface": "Ethernet1/2", "flaps": 5},
            {"ip": "192.0.2.10", "switchname": "N9K-1", "interface": "Ethernet1/3", "flaps": 8}
        ]

        Sample output if the "--include-metadata" parameter is provided is as follows:

        [
            {
                "ip": "192.0.2.10",
                "switchname": "N9K-1",
                "software_version": "9.3(7a)",
                "uptime": "7 day(s), 21 hour(s), 3 minute(s), 47 second(s)",
                "serial_number": "FOC1234ABCD",
                "hardware_model": "N9K-C93180YC-FX3",
                "interface": "Ethernet1/1",
                "flaps": 1
            },
            {
                "ip": "192.0.2.10",
                "switchname": "N9K-1",
                "software_version": "9.3(7a)",
                "uptime": "7 day(s), 21 hour(s), 3 minute(s), 48 second(s)",
                "serial_number": "FOC1234ABCD",
                "hardware_model": "N9K-C93180YC-FX3",
                "interface": "Ethernet1/2",
                "flaps": 5
            },
            {
                "ip": "192.0.2.10",
                "switchname": "N9K-1",
                "software_version": "9.3(7a)",
                "uptime": "7 day(s), 21 hour(s), 3 minute(s), 49 second(s)",
                "serial_number": "FOC1234ABCD",
                "hardware_model": "N9K-C93180YC-FX3",
                "interface": "Ethernet1/3",
                "flaps": 8
            }
        ]
    """
    # We can't use a TextFSM template here, as there is not a "show interface" template that
    # includes the interface reset counter.
    output = await command(conn, "show interface")
    interfaces = await analyze_interfaces_for_flaps(output)
    data = []
    for interface_name, flap_count in interfaces.items():
        if flap_count:
            flap_data = {
                "ip": conn.host,
                "switchname": await get_switchname(conn),
                "interface": interface_name,
                "flaps": flap_count,
            }
            if args.include_metadata:
                flap_data.update(await get_device_metadata(conn))
            data.append(flap_data)
    return data


async def get_switchname(conn: AsyncNXOSDriver) -> str:
    """Obtain the name of the switch configured with the "hostname" command.

    Args:
        conn (AsyncNXOSDriver): Scrapli driver representing the connection to the Nexus switch.

    Returns:
        str: Name of the switch as configured with the "hostname" global configuration command.
    """
    structured_output = await command(conn, "show version", structured=True)
    return structured_output[0]["hostname"]


async def get_device_metadata(conn: AsyncNXOSDriver) -> dict:
    """Obtain metadata about a switch.

    Obtain the following metadata about a switch:

    * NX-OS Software Version (e.g. 9.3(7a))
    * Switch Uptime (e.g. 7 day(s), 21 hour(s), 3 minute(s), 49 second(s))
    * Switch Serial Number (e.g. FOC1234ABCD)
    * Switch Hardware Model (e.g. N9K-C93180YC-FX)

    Args:
        conn (AsyncNXOSDriver): Scrapli driver representing the connection to the Nexus switch.

    Returns:
        dict: Represents metadata about the switch. Sample output is below:

        {
            "software_version": "9.3(7a)",
            "uptime": "7 day(s), 21 hour(s), 3 minute(s), 49 second(s)",
            "serial_number": "FOC1234ABCD",
            "hardware_model": "N9K-C93180YC-FX3",
        }
    """
    structured_output = await command(conn, "show version", structured=True)
    data = {
        "software_version": structured_output[0]["os"],
        "uptime": structured_output[0]["uptime"],
        "serial_number": structured_output[0]["serial"],
    }
    structured_output = await command(conn, "show module", structured=True)
    data["hardware_model"] = structured_output[0]["model"]
    return data


async def main() -> None:
    """Connect to multiple switches and identify regularly-flapping interfaces."""
    start_time = time.time()
    if not args.password:
        args.password = getpass(f"Input password for user account {args.username}: ")
    if connections := await validate_connections(
        args.switch_information, args.username, args.password
    ):
        if args.connect_only:
            logger.info("Bypassing interface analysis as requested")
        else:
            logger.info(
                "Identifying regularly-flapping interfaces (floor %s) across %s devices",
                args.interface_flap_floor,
                len(connections),
            )
            switch_data = await asyncio.gather(
                *[get_interface_flaps(c) for c in connections]
            )
            # switch_data will be a list of lists, since asyncio.gather() returns a list, and each
            # call of get_interface_flaps() also returns a list. Normalize this so that all data
            # is in a single list instead of nested lists.
            data = []
            for d in switch_data:
                data += d
            table = PrettyTable()
            if args.include_metadata:
                table.field_names = [
                    "IP/FQDN",
                    "Switch Name",
                    "Hardware Model",
                    "Serial Number",
                    "NX-OS Software Version",
                    "Switch Uptime",
                    "Interface",
                    "Number of Flaps",
                ]
                table.align["IP/FQDN"] = "l"
                table.align["Switch Name"] = "l"
                table.align["Hardware Model"] = "l"
                table.align["Serial Number"] = "l"
                table.align["NX-OS Software Version"] = "l"
                table.align["Switch Uptime"] = "l"
                table.align["Interface"] = "l"
            else:
                table.field_names = [
                    "IP/FQDN",
                    "Switch Name",
                    "Interface",
                    "Number of Flaps",
                ]
                table.align["IP/FQDN"] = "l"
                table.align["Switch Name"] = "l"
                table.align["Interface"] = "l"
            # Iterate through our interface data, sorting it from highest number of flaps to lowest
            # number of flaps.
            for d in sorted(data, key=lambda i: i["flaps"], reverse=True):
                if d["flaps"] >= args.interface_flap_floor:
                    if args.include_metadata:
                        table.add_row(
                            [
                                d.get("ip"),
                                d.get("switchname"),
                                d.get("hardware_model"),
                                d.get("serial_number"),
                                d.get("software_version"),
                                d.get("uptime"),
                                d.get("interface"),
                                d.get("flaps"),
                            ]
                        )
                    else:
                        table.add_row(
                            [
                                d.get("ip"),
                                d.get("switchname"),
                                d.get("interface"),
                                d.get("flaps"),
                            ]
                        )
            print(table)
    logger.info("Finished analysis in %.2f seconds", time.time() - start_time)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit()
