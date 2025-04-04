# sherpa-py-utils is available under the MIT License. https://github.com/Identicum/sherpa-py-utils/
# Copyright (c) 2025, Identicum - https://identicum.com/
#
# Author: Ezequiel O Sandoval - esandoval@identicum.com
#

from datetime import datetime
import sys
import re
from os.path import isfile, join, isdir
from os import listdir
from sherpa.utils import validators
import string
import secrets

class Logger(object):
    """
    Logger is an auxiliary class for granular logging
    Args: name (str): Class that invokes Logger instance
    Attributes:
        _name: name of the Logger instance
        _level: log level mode
        log_path: file to append log
    """

    def __init__(self, name, log_level="DEBUG", log_path="sherpa_logger.log"):
        self._name = name
        self._level = log_level
        self.log_path = log_path

    def trace(self, msg, *args):
        """
        TRACE log
        :param msg: msg to log
        """
        self._log("TRACE", msg, *args)

    def debug(self, msg, *args):
        """
        DEBUG log
        :param msg: msg to log
        """
        self._log("DEBUG", msg, *args)

    def info(self, msg, *args):
        """
        INFO log
        :param msg: msg to log
        """
        self._log("INFO", msg, *args)

    def warn(self, msg, *args):
        """
        WARN log
        :param msg: msg to log
        """
        self._log("WARN", msg, *args)

    def error(self, msg, *args):
        """
        ERROR log
        :param msg: msg to log
        """
        self._log("ERROR", msg, *args)

    def _log(self, function_log_level, msg, *args):
        """
        logs according level set
        :param function_log_level: log level
        :param msg: msg to log
        """
        function = sys._getframe(2).f_code.co_name
        if self._log_level(self._level) >= self._log_level(function_log_level):
            log_line = "{} || {} || {} || {} || {}".format(datetime.now().isoformat(sep=' ', timespec='milliseconds'),
                                                           function_log_level, self._name, function,
                                                           msg.format(*args) if len(args) > 0 else msg)
            try:
                print(log_line)
                f = open(self.log_path, 'a')
                f.write(log_line + "\n")
                f.close()
            except Exception:
                pass

    def _log_level(self, argument):
        """
        Validates if current level is available to log
        :return: Integer for comparison
        """
        switcher = {
            "ERROR": 1,
            "WARN": 2,
            "INFO": 3,
            "DEBUG": 4,
            "TRACE": 5
        }
        return switcher.get(argument, "Invalid level")


class Properties:
    """ Properties is an auxiliary class to handle Java-properties-like files
        """

    def __init__(self, props_file_path="./local.properties", default_props_file_path="./sample.properties",
                 param_prefix="{{", param_suffix="}}"):
        self.logger = Logger("Properties")
        self.param_prefix = param_prefix
        self.logger.trace("param prefix: {}", param_prefix)
        self.param_suffix = param_suffix
        self.logger.trace("param suffix: {}", param_suffix)
        self.logger.trace("Loading default properties...")
        self.properties = self._load(default_props_file_path).copy()
        self.logger.trace("Default properties: {}", self.properties)
        self.logger.trace("Loading local properties...")
        local_properties = self._load(props_file_path)
        self.logger.trace("Local properties: {}", self.properties)
        self.logger.trace("Merging Local properties into Default properties...")
        self.properties.update(local_properties)
        self.logger.trace("Properties: {}", self.properties)

    def get(self, key):
        return self.properties.get(key, None)

    def put(self, key, value):
        self.properties[key] = value

    def replace(self, path, extension=None):
        """
        replace keys inside a file or a folder with files with a related Property value
        :param path: path to file or folder
        :param extension: file extension
        :return:
        """
        files_path = [path] if not isdir(path) else [join(path, f) for f in listdir(path) if
                                                     isfile(join(path, f)) and f.endswith(extension)]
        for file_path in files_path:
            self._replace_file(file_path)

    def _load(self, file_path):
        """
        Read a property file passed as parameter
        """
        separator = "="
        comment_char = "#"
        props = {}
        self.logger.trace("Opening file from {}", file_path)
        with open(file_path, "rt") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith(comment_char):
                    key_value = line.split(separator)
                    key = key_value[0].strip()
                    value = separator.join(key_value[1:]).strip().strip('"')
                    props[key] = value
                    self.logger.trace("Key: {} - Value: {} loaded", key, value)
        return props

    def _replace_file(self, file_path):
        """
        Replace key values from Properties with its related value on a single file
        :param file_path: path to a single file
        :return:
        """
        self.logger.trace("Property replacement for {}", file_path)
        props_key_separator = dict()
        for k, v in self.properties.items():
            new_key = self.param_prefix + k + self.param_suffix
            props_key_separator[new_key] = v
        file_in = open(file_path, "rt")
        data = file_in.read()
        self.logger.trace("{} successfully read", file_path)
        regex_to_use = re.escape(self.param_prefix) + "[\\w.]+" + re.escape(self.param_suffix)
        self.logger.trace(regex_to_use)
        keys_to_replace_repeated = re.findall(re.compile(regex_to_use), data)
        self.logger.trace(keys_to_replace_repeated)
        keys_to_replace = set(keys_to_replace_repeated)
        self.logger.trace(keys_to_replace)
        pending_keys = keys_to_replace.difference(set(props_key_separator.keys()))
        if len(pending_keys) > 0:
            validators.raise_and_log(self.logger, ValueError, """
            The following values are not present in local.properties nor sample.properties, but are required by running app:

            {}
            """.format(pending_keys))
        for key in keys_to_replace:
            data = data.replace(key, props_key_separator.get(key))
        file_in.close()
        self.logger.trace("File read and replaced in memory, proceeding to dump in file")
        file_out = open(file_path, "wt")
        file_out.write(data)
        file_out.close()
        self.logger.trace("{} successfully replaced with Property values", file_path)

    def write(self, file_path):
        """
        writes the properties obj on a file as regular properties file
        Args:
            file_path: path to file to be created with properties
        """
        self.logger.debug("writing properties on {}", file_path)
        properties = ""

        for k, v in self.properties.items():
            properties = "{}\n{}={}".format(properties, k, v)

        file_out = open(file_path, "wt")
        file_out.write(properties)
        file_out.close()
        self.logger.debug("properties successfully wrote in {}", file_path)

def generate_random_password():
    """
    Returns a random 12 character password including 4 lowercase letters, 4 uppercase and 4 numbers

    Returns:
        str: Generated password
    """
    letters = string.ascii_letters
    random_letters = ""
    for i in range(8):
        if i < 4:
            random_letters += "".join(secrets.choice(letters).lower())
        else:
            random_letters += "".join(secrets.choice(letters).upper())
        
    digits = string.digits
    random_digits = ""
    for i in range(4):
        random_digits += "".join(secrets.choice(digits))
    # Random password example: ngnuKEVQ8708
    return random_letters + random_digits