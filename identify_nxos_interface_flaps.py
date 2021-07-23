#!/usr/bin/env python
"""Identifies and reports regularly-flapping interfaces on multiple Nexus switches."""

import time
import argparse
import logging
import sys
import asyncio

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


parser = argparse.ArgumentParser(
    description=(
        "Connects to multiple Nexus switches and identifies regularly-flapping interfaces, then "
        "ranks them from highest to lowest."
    )
)

# Optional arguments
parser.add_argument("--debug", "-d", help="Enable debug logging", action="store_true")
parser.add_argument(
    "--interface-flap-floor",
    "-f",
    help="Minimum quantity of interface flaps to be considered significant.",
    action="store",
)

args = parser.parse_args()

if args.debug:
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG,
        format="%(asctime)-15s %(levelname)-8s [%(funcName)20s] %(message)s",
    )
else:
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.INFO,
        format="%(asctime)-15s %(levelname)-8s [%(funcName)20s] %(message)s",
    )
    logging.getLogger("scrapli").setLevel(logging.WARNING)
    logging.getLogger("asyncssh").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


async def main() -> None:
    """Connect to multiple switches and identify regularly-flapping interfaces."""
    start_time = time.time()
    logger.info("Finished analysis in %.2f seconds", time.time() - start_time)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit()
