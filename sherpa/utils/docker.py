# sherpa-py-utils is available under the MIT License. https://github.com/Identicum/sherpa-py-utils/
# Copyright (c) 2025, Identicum - https://identicum.com/
#
# Author: Ezequiel O Sandoval - esandoval@identicum.com
#

from sherpa.utils import os_cmd


def stop_container(container_name, logger):
    """
    stop a docker container
    :param container_name: container to be stopped
    :param logger: sherpa log obj
    :return: execution value as str
    """
    return execute_container_action(container_name, "stop", logger)


def restart_container(container_name, logger):
    """
    restart a docker container
    :param container_name: container to be restarted
    :param logger: sherpa log obj
    :return: execution value as str
    """
    return execute_container_action(container_name, "restart", logger)


def remove_container(container_name, logger):
    """
    remove a docker container
    :param container_name: container to be removed
    :param logger: sherpa log obj
    :return: execution value as str
    """
    return execute_container_action(container_name, "rm", logger)


def execute_container_action(container_name, command_action, logger):
    """
    execute an accion in a docker container
    :param container_name: container to execute an action
    :param command_action: command action to be executed in the container
    :param logger: sherpa log obj
    :return: execution value as str
    """
    command = "docker {} {}".format(command_action, container_name)
    try:
        return_value = os_cmd.execute_in_bash(command, logger).decode().strip()
    except Exception as e:
        return_value = "Container '{}' does not exist?".format(container_name)
    logger.debug("return_value: '{}'", return_value)
    return return_value


def run_container(container_name, container_image, docker_parameters, cmd_parameters, logger, pull_image=True):
    """
    run a docker container
    :param container_name: container name
    :param container_image: container image to be used
    :param docker_parameters: docker parameters for docker execution
    :param cmd_parameters: cmd parameters for docker execution
    :param logger: sherpa log obj
    :param pull_image: flag that enables pull image action. Default 'True'
    :return: None
    """
    docker_parameters_str = " ".join(docker_parameters)
    logger.trace("docker_parameters_str: '{}'", docker_parameters_str)
    cmd_parameters_str = " ".join(cmd_parameters)
    logger.trace("cmd_parameters_str: '{}'", cmd_parameters_str)
    if pull_image:
        command = "docker pull {}".format(container_image)
        logger.debug("Executing command {}", command)
        os_cmd.execute_in_bash(command, logger)
    command = "docker run -d --name {} --restart=always {} {} {}".format(container_name, docker_parameters_str,
                                                                         container_image, cmd_parameters_str)
    logger.debug("Executing command '{}'", command)
    os_cmd.execute_in_bash(command, logger)
