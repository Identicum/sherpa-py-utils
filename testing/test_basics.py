#!/usr/bin/env python3

import os
import shutil
import sys

sys.path.insert(1, "../")
from sherpa.utils.basics import Logger
from sherpa.utils.basics import Properties
import sherpa.utils.basics as utils_basics


def main():
	properties = Properties("default.properties", "local.properties", "$(", ")")
	logger = Logger(os.path.basename(__file__), properties.get("log_level"), properties.get("log_file"))
	run(logger, properties)
	logger.info("{} finished.".format(os.path.basename(__file__)))


def test_variables_replacement(logger, properties):
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


def run(logger, properties):
	logger.info("{} starting.".format(os.path.basename(__file__)))

	test_variables_replacement(logger, properties)

	logger.info("Random password: {}", utils_basics.generate_random_password(num_lower=2, num_upper=3, num_digits=1))


if __name__ == "__main__":
	sys.exit(main())

