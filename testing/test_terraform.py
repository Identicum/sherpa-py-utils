#!/usr/bin/env python3

import os
import shutil
import sys

sys.path.insert(1, "../")
from sherpa.utils.basics import Logger
from sherpa.utils.basics import Properties
import sherpa.utils.terraform as utils_terraform


def main():
	properties = Properties("default.properties", "local.properties", "$(", ")")
	logger = Logger(os.path.basename(__file__), properties.get("log_level"), properties.get("log_file"))
	run(logger, properties)
	logger.info("{} finished.".format(os.path.basename(__file__)))



def run(logger, properties):
	logger.info("{} starting.".format(os.path.basename(__file__)))

	var_files = ["./variables.tfvars", "./variables2.tfvars"]
	utils_terraform.apply(logger, "./", var_files)
	utils_terraform.plan2binary(logger, "./", "./plan.binary", var_files)


if __name__ == "__main__":
	sys.exit(main())

