#!/usr/bin/env python3

import os
import shutil
import sys

sys.path.insert(1, "../sherpa/utils")
from basics import Logger
from basics import Properties


def main():
	properties = Properties("default.properties", "local.properties", "$(", ")")
	logger = Logger(os.path.basename(__file__), properties.get("log_level"), properties.get("log_file"))
	run(logger, properties)
	logger.info("{} finished.".format(os.path.basename(__file__)))


def run(logger, properties):
	logger.info("{} starting.".format(os.path.basename(__file__)))

	origin_file_path = "replace.xml"
	with open(origin_file_path, "r") as file_object:
		origin_data = file_object.read()
	logger.debug("origin_data: {}.", origin_data)

	temp_file_path = "/tmp/replace.tmp"
	shutil.copyfile(origin_file_path, temp_file_path)
	properties.replace(temp_file_path)
	with open(temp_file_path, "r") as file_object:
		replaced_data = file_object.read()
	logger.debug("replaced_data: {}.", replaced_data)


if __name__ == "__main__":
	sys.exit(main())

