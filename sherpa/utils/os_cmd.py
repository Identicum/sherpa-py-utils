# sherpa-py-utils is available under the MIT License. https://github.com/Identicum/sherpa-py-utils/
# Copyright (c) 2024, Identicum - https://identicum.com/
#
# Author: Ezequiel O Sandoval - esandoval@identicum.com
#

import os
import psutil
import shutil
import subprocess
from sherpa.utils import validators


def check_yum_package(package_name, logger):
	"""
	check if a yum package is installed
	:param package_name: name to be checked
	:param logger: sherpa log obj
	:return: boolean
	"""
	logger.trace("Checking if package '{}' is installed.", package_name)
	command = "yum list installed {}".format(package_name)
	try:
		execute_in_bash(command, logger)
	except:
		logger.trace("Package '{}' is not installed.", package_name)
		return False
	logger.trace("Package '{}' is already installed.", package_name)
	return True


def install_yum_package(package_name, logger):
	"""
	install a package if it is not installed
	:param package_name: package name to be installed
	:param logger: sherpa log obj
	:return: None
	"""
	if check_yum_package(package_name, logger):
		logger.trace("{} package already installed. Do nothing.")
	else:
		command = "yum -y install {}".format(package_name)
		logger.debug("Installing package '{}' using command '{}'", package_name, command)
		execute_in_bash(command, logger)


def install_pip_library(library_name, logger):
	"""
	install a PIP library
	:param library_name: library_name name to be installed
	:param logger: sherpa log obj
	:return: None
	"""
	command = "python3 -m pip install {}".format(library_name)
	logger.debug("Installing library '{}' using command '{}'", library_name, command)
	execute_in_bash(command, logger)


def check_local_rpm(rpm_path, logger):
	"""
	check if local rpm exists
	:param rpm_path: path to the local rpm
	:param logger: sherpa log obj
	:return: Boolean
	"""
	logger.trace("rpm_path: '{}'", rpm_path)
	if not os.path.isfile(rpm_path):
		validators.raise_and_log(logger, IOError, "File does not exist.", rpm_path)
	rpm_file = os.path.split(rpm_path)[1]
	logger.trace("rpm_file: '{}'", rpm_file)
	if not rpm_file.endswith('.rpm'):
		validators.raise_and_log(logger, IOError, "Wrong file extension", rpm_file)
	rpm = rpm_file[:-4]
	logger.trace("rpm: '{}'", rpm)
	command = "rpm -q {}".format(rpm)
	logger.trace("Checking if '{}' is installed, using command: '{}'.", rpm, command)
	try:
		execute_in_bash(command, logger)
	except:
		logger.debug("RPM '{}' is not installed.", rpm_file)
		return False
	logger.trace("RPM '{}' is already installed.", rpm)
	return True


def install_local_rpm(rpm_file, logger):
	"""
	install a local rpm file
	:param rpm_file:  path to the file
	:param logger: sherpa log obj
	:return:
	"""
	if check_local_rpm(rpm_file, logger):
		logger.trace("{} RPM already installed. Do nothing.", rpm_file)
	else:
		command = "yum -y install {}".format(rpm_file)
		logger.debug("Installing rpm '{}' using command '{}'", rpm_file, command)
		execute_in_bash(command, logger)


def download_file(url, local_file, logger):
	"""
	download a file with wget
	:param url: url to be queried
	:param local_file: path and name of the file in local system (after download)
	:param logger: sherpa log obj
	:return: None
	"""
	download_command = "wget " + url + " -O " + local_file
	logger.debug("Downloading file '{}'.", download_command)
	execute_in_bash(download_command, logger)


def check_disk_space(partition, requiredMB, logger):
	"""
	Checks if disk has enough space according to the requiredMB
	:param partition: partition to be checked
	:param requiredMB: amount of MB required in check
	:param logger: sherpa log obj
	:return: None (throws an exception if the requiredMB is not satisfied)
	"""
	logger.debug("Checking partition: '{}' for '{}' free MB", partition, requiredMB)
	total, used, free = shutil.disk_usage(partition)
	free_mb = free // (2**20)
	logger.debug("Free disk spage: '{}' MB.", free_mb)
	if free_mb < requiredMB:
		validators.raise_and_log(logger, IOError, "Not enough disk space in partition '{}'. Required: {}.  Available: {}.", partition, requiredMB, free_mb)


def check_total_mem(requiredMB, logger):
	"""
	Checks if total mem has enough space according to the requiredMB
	:param requiredMB: amount of MB required in check
	:param logger: sherpa log obj
	:return:
	"""
	logger.debug("checking total memory for '{}' MB", requiredMB)
	mem = psutil.virtual_memory()
	total_mb = mem.total // (2**20)
	logger.debug("Total memory: '{}' MB.", total_mb)
	if total_mb < requiredMB:
		validators.raise_and_log(logger, IOError, "Not enough RAM memory. Required: {}.  Available: {}.", requiredMB, total_mb)


def execute_in_bash(command, logger=None):
	"""
	execute a command in bash
	:param command: command to execute
	:param logger: sherpa log obj
	:return: str that represents output
	"""
	output = subprocess.check_output(command, shell=True)
	if logger is not None:
		logger.trace("Command output: ", output)
	return output

