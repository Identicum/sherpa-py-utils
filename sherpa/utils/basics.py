# sherpa-py-utils is available under the MIT License. https://github.com/Identicum/sherpa-py-utils/
# Copyright (c) 2026, Identicum - https://identicum.com/
#
# Author: Ezequiel O Sandoval - esandoval@identicum.com
#

from datetime import datetime
from importlib.metadata import version
from os.path import isfile, join, isdir
from os import listdir
from pathlib import Path
import re
import secrets
from sherpa.utils import validators
import string
import sys

class Logger(object):
    """
    Logger is an auxiliary class for granular logging
    Args: name (str): Class that invokes Logger instance
    Attributes:
        _name: name of the Logger instance
        _level: log level mode
        log_path: file to append log
    """

    def __init__(self, name, log_level="DEBUG", log_path="sherpa_logger.log", stdout=True):
        self._name = name
        self._level = log_level
        self.log_path = log_path
        self.stdout = stdout
        self.debug("Logger version: " + version("sherpa-py-utils"))

    def trace(self, msg, *args):
        """
        TRACE log
        :param msg: msg to log
        """
        return self._log("TRACE", msg, *args)

    def debug(self, msg, *args):
        """
        DEBUG log
        :param msg: msg to log
        """
        return self._log("DEBUG", msg, *args)

    def info(self, msg, *args):
        """
        INFO log
        :param msg: msg to log
        """
        return self._log("INFO", msg, *args)

    def warn(self, msg, *args):
        """
        WARN log
        :param msg: msg to log
        """
        return self._log("WARN", msg, *args)

    def error(self, msg, *args):
        """
        ERROR log
        :param msg: msg to log
        """
        return self._log("ERROR", msg, *args)

    def _log(self, function_log_level, msg, *args):
        """
        logs according level set
        :param function_log_level: log level
        :param msg: msg to log
        """
        frame = sys._getframe(1)
        # Method names to skip when walking the stack for the calling function's name, so wrapper/proxy objects exposing the same method names don't get misattributed.
        _LOG_METHOD_NAMES = {"trace", "debug", "info", "warn", "error", "_log"}
        while frame and frame.f_code.co_name in _LOG_METHOD_NAMES:
            frame = frame.f_back
        function = frame.f_code.co_name if frame else "?"
        if self._log_level(self._level) >= self._log_level(function_log_level):
            log_line = "{} || {} || {} || {} || {}".format(datetime.now().isoformat(sep=' ', timespec='milliseconds'),
                                                           function_log_level.ljust(5), self._name, function,
                                                           msg.format(*args) if len(args) > 0 else msg)
            try:
                if self.stdout:
                    print(log_line)
                f = open(self.log_path, 'a')
                f.write(log_line + "\n")
                f.close()
            except Exception:
                pass
            return log_line
        return None

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


def _parse_properties_file(file_path):
    """
    Read a property file into a plain dict, ignoring comments/blank lines.
    Module-level so it can be reused without a Properties/Logger instance.
    """
    separator = "="
    comment_char = "#"
    props = {}
    with open(file_path, "rt") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith(comment_char):
                key_value = line.split(separator)
                key = key_value[0].strip()
                value = separator.join(key_value[1:]).strip().strip('"')
                props[key] = value
    return props


_MANIFEST_TAG_RE = re.compile(r"^#\s*@(\w+)(?:\s+(.*))?$")


def _parse_manifest_specs(file_path):
    """
    Parse a default.properties-style file, reading the `# @tag value` comment
    block directly above each key into a spec: {type, values, required, required_if}.
    required_if is a list of AND-groups of (key, value) tuples; a key is
    required if ANY group matches (OR across groups, AND within a group).
    Returns (specs, values), values being the plain key -> value dict.
    """
    specs = {}
    values = {}
    pending = {}
    with open(file_path, "rt") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                pending = {}
                continue
            tag_match = _MANIFEST_TAG_RE.match(line)
            if tag_match:
                tag, tag_value = tag_match.group(1), (tag_match.group(2) or "").strip()
                pending.setdefault(tag, []).append(tag_value)
                continue
            if line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            values[key] = value.strip().strip('"')
            required_if = []
            for raw_condition_group in pending.get("required_if", []):
                group = []
                for condition in raw_condition_group.split(","):
                    cond_key, _, cond_value = condition.partition("=")
                    group.append((cond_key.strip(), cond_value.strip()))
                required_if.append(group)
            specs[key] = {
                "type": pending.get("type", [None])[0],
                "values": [v.strip() for v in pending["values"][0].split(",")] if pending.get("values") else [],
                "required": pending.get("required", [""])[0].strip().lower() == "true",
                "required_if": required_if,
            }
            pending = {}
    return specs, values


def validate_properties_file(properties_file_path, default_properties_file_path, logger=None):
    """
    Validate that properties_file_path satisfies the @type/@values/@required/
    @required_if specs declared in comments above each key in
    default_properties_file_path. Values are checked as effective values:
    default_properties_file_path's value overridden by properties_file_path's,
    if present.
    Raises ValueError listing every violation found. Meant to run before a
    Properties instance is created, so it takes file paths rather than a
    Properties object.
    :param properties_file_path: path to the overriding properties file (e.g. local.properties)
    :param default_properties_file_path: path to the annotated default properties file (e.g. default.properties)
    :param logger: Identicum logger - if None, a default one is created
    """
    logger = logger if logger is not None else Logger("basics")
    specs, default_values = _parse_manifest_specs(default_properties_file_path)
    override_values = _parse_properties_file(properties_file_path)
    effective = default_values.copy()
    effective.update(override_values)

    errors = []
    unknown_keys = sorted(set(override_values) - set(specs))
    for key in unknown_keys:
        errors.append("{} is not a recognized property (check for typos)".format(key))

    for key, spec in specs.items():
        value = effective.get(key, "")
        if spec["required"] and not value:
            errors.append("{} is required but has no value".format(key))
            continue
        if not value:
            for group in spec["required_if"]:
                if all(effective.get(cond_key, "") == cond_value for cond_key, cond_value in group):
                    condition = " and ".join("{}={}".format(cond_key, cond_value) for cond_key, cond_value in group)
                    errors.append("{} is required when {}".format(key, condition))
                    break
            continue
        if spec["type"] == "enum" and spec["values"] and value not in spec["values"]:
            errors.append("{} has value '{}', expected one of {}".format(key, value, spec["values"]))
        elif spec["type"] == "bool" and value.lower() not in ("true", "false"):
            errors.append("{} has value '{}', expected true/false".format(key, value))
        elif spec["type"] == "int" and not re.fullmatch(r"-?\d+", value):
            errors.append("{} has value '{}', expected an integer".format(key, value))

    if errors:
        validators.raise_and_log(logger, ValueError, "{} failed properties validation:\n  - {}".format(
            properties_file_path, "\n  - ".join(errors)))
    return True


class Properties:
    """ Properties is an auxiliary class to handle Java-properties-like files
        """

    def __init__(self, props_file_path="./local.properties", default_props_file_path="./sample.properties", param_prefix="{{", param_suffix="}}", logger=None):
        self.logger = logger if logger is not None else Logger("Properties")
        self.logger.debug("Properties version: " + version("sherpa-py-utils"))
        self.param_prefix = param_prefix
        self.param_suffix = param_suffix
        self.logger.trace("props_file_path: {}, default_props_file_path: {}, param_prefix: {}, param_suffix: {}", props_file_path, default_props_file_path, self.param_prefix, self.param_suffix)
        # self.logger.trace("Loading default properties...")
        self.properties = self._load(default_props_file_path).copy()
        # self.logger.trace("Default properties: {}", self.properties)
        # self.logger.trace("Loading local properties...")
        local_properties = self._load(props_file_path)
        # self.logger.trace("Local properties: {}", self.properties)
        # self.logger.trace("Merging Local properties into Default properties...")
        self.properties.update(local_properties)
        # self.logger.trace("Properties: {}", self.properties)

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
        self.logger.trace("Opening file from {}", file_path)
        return _parse_properties_file(file_path)

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

class Template:
    """
    Template renders "IF ... ENDIF" conditional blocks embedded in a text file as
    comments, evaluated against a Properties instance.

    Directives look like (default XML/HTML comment_start/comment_end):
        <!-- IF google.enabled --> ... <!-- ENDIF -->
        <!-- IF google.groups == "XXX" --> ... <!-- ENDIF -->
    Blocks may repeat any number of times in a file and may nest. A directive
    that sits alone on its own line also consumes that line's indentation and
    trailing newline, so removing a block doesn't leave a blank line behind; a
    directive sharing a line with other content is left untouched around it.

    comment_start/comment_end are configurable so other comment styles can be
    used for non-XML files, e.g. a line-comment style for Terraform/HCL:
        Template(properties, comment_start="#", comment_end="")
        # IF google.enabled
        ...
        # ENDIF
    Pass a falsy comment_end for line-comment styles, where the directive runs
    to the end of the line instead of to a closing delimiter.
    """

    def __init__(self, properties, logger=None, comment_start="<!--", comment_end="-->"):
        self.properties = properties
        self.logger = logger if logger is not None else Logger("Template")
        self.logger.debug("Template version: " + version("sherpa-py-utils"))
        self.comment_start = comment_start
        self.comment_end = comment_end
        self._directive_re = self._build_directive_re(comment_start, comment_end)

    def render(self, content):
        """
        Apply IF/ENDIF conditional blocks to content, evaluated against self.properties.
        Always returns a string (possibly blank, if everything was excluded).
        :param content: str to render
        :return: rendered str
        """
        tokens = self._tokenize(content)
        rendered, end_index, terminator = self._render_tokens(tokens, 0, True)
        if terminator is not None:
            validators.raise_and_log(self.logger, ValueError, "ENDIF found with no matching IF")
        assert end_index == len(tokens)
        return rendered

    def process_file(self, input_path, output_path, discard_empty_file=True):
        """
        Read input_path, render it, and write the result to output_path.
        :param input_path: file to read
        :param output_path: file to write the rendered content to
        :param discard_empty_file: if True, skip writing (and return None) when the
            rendered content is blank, e.g. because it was entirely inside a false IF.
        :return: output_path as a Path, or None if the file was discarded
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        self.logger.debug("Rendering {}", input_path)
        content = input_path.read_text()
        rendered = self.render(content)
        if discard_empty_file and not rendered.strip():
            self.logger.debug("{} fully excluded, skipping.", input_path)
            return None
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered)
        self.logger.debug("Rendered {} -> {}", input_path, output_path)
        return output_path

    def process_folder(self, input_dir, output_dir, discard_empty_file=True):
        """
        Recursively render every file under input_dir, mirroring its relative
        folder structure into output_dir. A destination subfolder is only created
        if a file is actually written into it.
        :param input_dir: folder to read files from, recursively
        :param output_dir: folder to mirror rendered files into
        :param discard_empty_file: see process_file
        :return: list of Path written
        """
        input_dir = Path(input_dir)
        output_dir = Path(output_dir)
        written = []
        for file_path in sorted(p for p in input_dir.rglob("*") if p.is_file()):
            relative_path = file_path.relative_to(input_dir)
            destination = self.process_file(file_path, output_dir / relative_path, discard_empty_file=discard_empty_file)
            if destination is not None:
                written.append(destination)
        return written

    def _build_directive_re(self, comment_start, comment_end):
        start = re.escape(comment_start)
        if comment_end:
            end = re.escape(comment_end)
            pattern = r"[ \t]*" + start + r"\s*(IF|ENDIF)\b(.*?)" + end + r"[ \t]*\n?"
            return re.compile(pattern, re.DOTALL)
        # Line-comment style (no closing delimiter): directive runs to end of line.
        pattern = r"[ \t]*" + start + r"\s*(IF|ENDIF)\b(.*?)[ \t]*(?:\n|$)"
        return re.compile(pattern)

    def _tokenize(self, content):
        tokens = []
        pos = 0
        for match in self._directive_re.finditer(content):
            if match.start() > pos:
                tokens.append(("text", content[pos:match.start()]))
            tokens.append(("directive", match.group(1), match.group(2).strip()))
            pos = match.end()
        if pos < len(content):
            tokens.append(("text", content[pos:]))
        return tokens

    def _render_tokens(self, tokens, index, take):
        output = []
        while index < len(tokens):
            token = tokens[index]
            if token[0] == "text":
                if take:
                    output.append(token[1])
                index += 1
                continue
            _, kind, expr = token
            if kind == "ENDIF":
                return "".join(output), index, kind
            branch_take = take and self._evaluate_condition(expr)
            branch_content, index, terminator = self._render_tokens(tokens, index + 1, branch_take)
            if terminator != "ENDIF":
                validators.raise_and_log(self.logger, ValueError, "IF '{}' has no matching ENDIF".format(expr))
            output.append(branch_content)
            index += 1  # consume the ENDIF token itself
        return "".join(output), index, None

    def _evaluate_condition(self, expr):
        negate = False
        if expr.startswith("!"):
            negate = True
            expr = expr[1:].strip()
        elif expr.lower().startswith("not "):
            negate = True
            expr = expr[4:].strip()

        if not expr:
            validators.raise_and_log(self.logger, ValueError, "IF directive has an empty condition")

        if "==" in expr:
            key, _, raw_value = expr.partition("==")
            result = self._property_value(key.strip()) == self._strip_quotes(raw_value.strip())
        elif "!=" in expr:
            key, _, raw_value = expr.partition("!=")
            result = self._property_value(key.strip()) != self._strip_quotes(raw_value.strip())
        else:
            result = self._property_value(expr).lower() == "true"
        return not result if negate else result

    def _property_value(self, key):
        value = self.properties.get(key)
        return value.strip() if value is not None else ""

    @staticmethod
    def _strip_quotes(value):
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            return value[1:-1]
        return value


def generate_random_password(num_lower=4, num_upper=4, num_digits=4):
    """
    Generate a random password
    :param num_lower: Number of lowercase characters
    :param num_upper: Number of uppercase characters
    :param num_digits: Number of digits
    :return: a str with the generated password
    """

    letters = string.ascii_letters

    lower_letters = ""
    for i in range(num_lower):
        lower_letters += "".join(secrets.choice(letters).lower())

    upper_letters = ""
    for i in range(num_upper):
        upper_letters += "".join(secrets.choice(letters).upper())
        
    digits = string.digits
    random_digits = ""
    for i in range(num_digits):
        random_digits += "".join(secrets.choice(digits))

    return lower_letters + upper_letters + random_digits