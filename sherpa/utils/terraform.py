#!/usr/bin/env python3

import os
from sherpa.utils import os_cmd
from sherpa.utils.basics import Logger


def init(logger: Logger, objectsFolder: str):
	if not os.path.exists(objectsFolder):
		logger.error("{} directory does not exist.", objectsFolder)
		return
	cmd = "cd {} && terraform init -upgrade -no-color > /dev/null".format(objectsFolder)
	logger.debug("Executing '{}'", cmd)
	output = os_cmd.execute_in_bash(cmd, logger)
	# ToDo: check if terraform init was successful
	return output


def select_workspace(logger: Logger, objectsFolder: str, workspace: str):
	cmd = "cd {} && terraform workspace select {}".format(objectsFolder, workspace)
	logger.debug("Executing '{}'", cmd)
	output = os_cmd.execute_in_bash(cmd, logger)
	# ToDo: check if terraform select was successful
	return output


def create_workspace(logger: Logger, objectsFolder: str, workspace: str):
	if not os.path.exists("{}/terraform.tfstate.d/{}".format(objectsFolder, workspace)):
		cmd = "cd {} && terraform workspace new {}".format(objectsFolder, workspace)
		logger.debug("Executing '{}'", cmd)
		output = os_cmd.execute_in_bash(cmd, logger)
		# ToDo: check if terraform create was successful
	else:
		output = "Workspace '{}' already exists in '{}'".format(workspace, objectsFolder)
		logger.debug(output)
	return output


def apply(logger: Logger, objectsFolder: str, varFiles=[]):
	cmd = "cd {} && terraform apply --auto-approve".format(objectsFolder)
	cmd += " -var-file={}".format(" -var-file=".join(varFiles)) if varFiles else ""
	logger.debug("Executing '{}'", cmd)
	output = os_cmd.execute_in_bash(cmd, logger)
	# ToDo: check if terraform apply was successful
	return output


def delete_workspace_state(logger: Logger, objectsFolder: str, workspace: str):
	logger.debug("Deleting terraform state (terraform destroy is never executed in local)")
	cmd = "rm -f {}/terraform.tfstate.d/{}/terraform.tfstate".format(objectsFolder, workspace)
	logger.debug("Executing '{}'", cmd)
	output = os_cmd.execute_in_bash(cmd, logger)
	# ToDo: check if delete was successful
	return output


def plan2binary(logger: Logger, objectsFolder: str, binaryPlan: str, varFiles=[]):
	cmd = "cd {} && terraform plan".format(objectsFolder)
	cmd += " -var-file={}".format(" -var-file=".join(varFiles)) if varFiles else ""
	cmd += " -out={} -no-color > /dev/null".format(binaryPlan)
	logger.debug("Executing '{}'", cmd)
	output = os_cmd.execute_in_bash(cmd, logger)
	# ToDo: check if terraform plan was successful
	return output


def show_binary2json(logger: Logger, objectsFolder: str, binaryPlan: str, jsonPlan: str):
	cmd = "cd {} && terraform show -json {} > {}".format(objectsFolder, binaryPlan, jsonPlan)
	logger.debug("Executing '{}'", cmd)
	output = os_cmd.execute_in_bash(cmd, logger)
	# ToDo: check if terraform show was successful
	return output
