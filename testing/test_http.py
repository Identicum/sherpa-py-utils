#!/usr/bin/env python3

import os
import shutil
import sys

sys.path.insert(1, "../")
from sherpa.utils.basics import Logger
from sherpa.utils.basics import Properties
from sherpa.utils.http import wait_for_endpoint


def main():
	properties = Properties("default.properties", "local.properties", "$(", ")")
	logger = Logger(os.path.basename(__file__), properties.get("log_level"), properties.get("log_file"))
	run(logger)
	logger.info("{} finished.".format(os.path.basename(__file__)))


def test_wait_for_endpoint(logger):
	wait_for_endpoint(
		url="https://identicum.com",
		iterations=2,
		interval=10,
		logger=logger,
		valid_status_code_range=range(200, 399)
	)


def run(logger):
	logger.info("{} starting.".format(os.path.basename(__file__)))
	test_wait_for_endpoint(logger)


if __name__ == "__main__":
	sys.exit(main())

