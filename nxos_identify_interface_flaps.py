#!/usr/bin/env python
"""Identifies and reports regularly-flapping interfaces on multiple Nexus switches."""

from typing import List
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

LINK_FLAP_PATTERN = re.compile(
    r"^(?P<datetime>\d+\s+\S+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+%ETHPORT-5-IF_DOWN_LINK_FAILURE:\s+Interface\s+(?P<interface>\S+)\s+is\s+down\s+\(Link\s+failure\)"  # noqa: E501
)


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


async def analyze_syslog_for_interface_flaps(syslog: str) -> List[dict]:
    """Analyze syslog output for interface flaps.

    Iterates through the output of "show logging logfile" from a Nexus switch and identifies syslogs
    that indicate an interface flapped. A flap is identified through a syslog similar to the
    following:

    2012 Jun 22 16:52:08 switch %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/3 is down (Link failure)  # noqa: E501

    Args:
        syslog (str): The output of "show logging logfile" from a Nexus switch.

    Returns:
        List[dict]: List of dictionaries representing flapped interfaces on this switch. Sample
        output is as follows:

        [
            {"Ethernet1/1": 1},
            {"Ethernet1/2": 5},
            {"Ethernet1/3": 8}
        ]
    """
    logger.debug("%s entries in syslog", syslog.splitlines())
    interfaces = {}
    for line in syslog.splitlines():
        if res := LINK_FLAP_PATTERN.search(line):
            interface = res.groupdict()["interface"]
            try:
                interfaces[interface] += 1
            except KeyError:
                interfaces[interface] = 1
    return interfaces


async def get_interface_flaps(conn: AsyncNXOSDriver) -> List[dict]:
    """Identify interface flaps on a switch.

    Fetches the output of "show logging logfile" from a Nexus switch and passes it into
    analyze_syslog_for_interface_flaps() for analysis. The results from this coroutine are modified
    such that the switch's IP and hostname (per CLI prompt) are associated with each interface and
    its quantity of flaps.

    Args:
        conn (AsyncNXOSDriver): Scrapli driver representing the connection to the Nexus switch.

    Returns:
        List[dict]: List of dictionaries representing each unique (device, interface, number of
        flaps) tuple. Sample output is as follows:

        [
            {"ip": "192.0.2.10", "hostname": "N9K-1", "interface": "Ethernet1/1", "flaps": 1},
            {"ip": "192.0.2.10", "hostname": "N9K-1", "interface": "Ethernet1/2", "flaps": 5},
            {"ip": "192.0.2.10", "hostname": "N9K-1", "interface": "Ethernet1/3", "flaps": 8}
        ]
    """
    response = await conn.send_command("show logging logfile")
    response.raise_for_status()
    output = response.result
    interfaces = await analyze_syslog_for_interface_flaps(output)
    prompt = await conn.get_prompt()
    data = []
    for interface_name, flap_count in interfaces.items():
        if flap_count:
            data.append(
                {
                    "ip": conn.host,
                    "hostname": prompt.replace("#", ""),
                    "interface": interface_name,
                    "flaps": flap_count,
                }
            )
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
            table.field_names = ["IP", "Hostname", "Interface", "Number of Flaps"]
            table.align["IP"] = "l"
            table.align["Hostname"] = "l"
            table.align["Interface"] = "l"
            # Iterate through our interface data, sorting it from highest number of flaps to lowest
            # number of flaps.
            for d in sorted(data, key=lambda i: i["flaps"], reverse=True):
                if d["flaps"] > args.interface_flap_floor:
                    table.add_row(d.values())
            print(table)
    logger.info("Finished analysis in %.2f seconds", time.time() - start_time)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit()
