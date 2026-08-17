#!/usr/bin/env python3
#
# Executable spec for spec validation: the standalone validate_properties_file and
# the Properties validate constructor flag, which share the same checks.
#

import contextlib
import os
import sys
import tempfile

sys.path.insert(1, "../")
from sherpa.utils.basics import Logger
from sherpa.utils.basics import Properties
from sherpa.utils.basics import validate_properties_file


# Tests use their own namespace: SHERPA_ would make them depend on whatever the
# developer happens to have exported in their shell.
PREFIX = "TESTPFX_"

# master_password is @required but carries a default, so it only fails once a later
# layer blanks it. iga.google.client_id is the @required_if case, empty by default.
ANNOTATED_DEFAULT = """
# @section Log
# @description Sherpa scripts log level
# @type enum
# @values TRACE,DEBUG,INFO,WARN,ERROR
# @default INFO
log.level=INFO

# @section SMTP
# @type int
# @default 25
smtp.port=25

# @section IGA - Google
# @type bool
# @default false
iga.google.enabled=false

# @section IGA - Google
# @type string
# @required_if iga.google.enabled=true
iga.google.client_id=

# @section Core
# @type string
# @required true
master_password=fromdefault

# @section Core
# @type string
# @default /opt/app
path=/opt/app
"""


@contextlib.contextmanager
def environment(variables):
	"""
	Apply the given variables to os.environ for the duration of the block, then
	restore the original environment. os.environ is process-global, so without
	this one test leaks into the next.
	"""
	saved = os.environ.copy()
	os.environ.update(variables)
	try:
		yield
	finally:
		os.environ.clear()
		os.environ.update(saved)


def write_files(tmp_dir, default_text, local_entries):
	default_path = os.path.join(tmp_dir, "default.properties")
	local_path = os.path.join(tmp_dir, "local.properties")
	with open(default_path, "wt") as f:
		f.write(default_text)
	with open(local_path, "wt") as f:
		for key, value in local_entries.items():
			f.write("{}={}\n".format(key, value))
	return default_path, local_path


def make_properties(logger, tmp_dir, local_entries=None, default_text=None, **kwargs):
	default_path, local_path = write_files(tmp_dir, default_text or ANNOTATED_DEFAULT, local_entries or {})
	return Properties(local_path, default_path, "$(", ")", logger, **kwargs)


def expect_error(error_type, reason, callable_obj):
	"""
	Assert callable_obj raises error_type, and return the message so that a test can
	also check what the error points at.
	"""
	try:
		callable_obj()
	except error_type as e:
		return str(e)
	raise AssertionError("expected {} because {}".format(error_type.__name__, reason))


# --- the flag is opt-in: existing call sites must not start failing -----------------

def test_invalid_values_pass_without_the_flag(logger, tmp_dir):
	properties = make_properties(logger, tmp_dir, {"log.level": "verbose", "smtp.port": "abc"})
	assert properties.get("log.level") == "verbose", "without validate the values are loaded as-is"
	logger.info("test_invalid_values_pass_without_the_flag passed")


def test_local_only_key_passes_without_the_flag(logger, tmp_dir):
	# Properties has always let the local layer introduce keys the default file does
	# not have; turning that into an error by default would break existing callers.
	properties = make_properties(logger, tmp_dir, {"not.in.default": "x"})
	assert properties.get("not.in.default") == "x", "without validate the local layer may still add keys"
	logger.info("test_local_only_key_passes_without_the_flag passed")


def test_validate_is_keyword_only(logger, tmp_dir):
	default_path, local_path = write_files(tmp_dir, ANNOTATED_DEFAULT, {})
	expect_error(TypeError, "validate must not be accepted positionally",
				 lambda: Properties(local_path, default_path, "$(", ")", logger, True))
	logger.info("test_validate_is_keyword_only passed")


# --- a valid configuration validates ------------------------------------------------

def test_valid_configuration_passes(logger, tmp_dir):
	properties = make_properties(logger, tmp_dir, {"log.level": "DEBUG", "smtp.port": "1025"}, validate=True)
	assert properties.get("log.level") == "DEBUG"
	logger.info("test_valid_configuration_passes passed")


def test_defaults_alone_pass(logger, tmp_dir):
	properties = make_properties(logger, tmp_dir, {}, validate=True)
	assert properties.get("master_password") == "fromdefault"
	logger.info("test_defaults_alone_pass passed")


# --- the checks themselves ----------------------------------------------------------

def test_enum_violation_raises(logger, tmp_dir):
	message = expect_error(ValueError, "verbose is not one of the declared @values",
						   lambda: make_properties(logger, tmp_dir, {"log.level": "verbose"}, validate=True))
	assert "log.level" in message and "verbose" in message, message
	logger.info("test_enum_violation_raises passed")


def test_bool_violation_raises(logger, tmp_dir):
	message = expect_error(ValueError, "yes is not true/false",
						   lambda: make_properties(logger, tmp_dir, {"iga.google.enabled": "yes"}, validate=True))
	assert "iga.google.enabled" in message, message
	logger.info("test_bool_violation_raises passed")


def test_int_violation_raises(logger, tmp_dir):
	message = expect_error(ValueError, "abc is not an integer",
						   lambda: make_properties(logger, tmp_dir, {"smtp.port": "abc"}, validate=True))
	assert "smtp.port" in message, message
	logger.info("test_int_violation_raises passed")


def test_required_blanked_by_local_raises(logger, tmp_dir):
	message = expect_error(ValueError, "a @required key was blanked by the local layer",
						   lambda: make_properties(logger, tmp_dir, {"master_password": ""}, validate=True))
	assert "master_password" in message, message
	logger.info("test_required_blanked_by_local_raises passed")


def test_unknown_key_raises(logger, tmp_dir):
	message = expect_error(ValueError, "log.levl is not in the catalog",
						   lambda: make_properties(logger, tmp_dir, {"log.levl": "DEBUG"}, validate=True))
	assert "log.levl" in message and "typos" in message, message
	logger.info("test_unknown_key_raises passed")


def test_every_violation_is_reported_at_once(logger, tmp_dir):
	message = expect_error(ValueError, "the configuration has three separate problems",
						   lambda: make_properties(logger, tmp_dir,
												   {"log.level": "verbose", "smtp.port": "abc", "log.levl": "x"},
												   validate=True))
	for expected in ("log.level", "smtp.port", "log.levl"):
		assert expected in message, "{} missing from: {}".format(expected, message)
	logger.info("test_every_violation_is_reported_at_once passed")


# --- validation runs once, on the merged result, not layer by layer -----------------

def test_default_placeholder_fixed_by_local_passes(logger, tmp_dir):
	# The default file is allowed to hold a non-conforming placeholder as long as a
	# later layer replaces it: only the resolved value is validated.
	placeholder_default = ANNOTATED_DEFAULT.replace("smtp.port=25", "smtp.port=CHANGEME")
	properties = make_properties(logger, tmp_dir, {"smtp.port": "1025"},
								 default_text=placeholder_default, validate=True)
	assert properties.get("smtp.port") == "1025"
	logger.info("test_default_placeholder_fixed_by_local_passes passed")


def test_required_if_triggered_by_local_and_unsatisfied_raises(logger, tmp_dir):
	message = expect_error(ValueError, "enabling google makes client_id required and nothing provides it",
						   lambda: make_properties(logger, tmp_dir, {"iga.google.enabled": "true"}, validate=True))
	assert "iga.google.client_id" in message and "iga.google.enabled=true" in message, message
	logger.info("test_required_if_triggered_by_local_and_unsatisfied_raises passed")


def test_required_if_triggered_by_local_and_satisfied_by_env_passes(logger, tmp_dir):
	# This is why validation cannot run layer by layer: after the local layer the
	# configuration is incomplete, and the environment layer is what completes it.
	with environment({PREFIX + "IGA_GOOGLE_CLIENT_ID": "an-id"}):
		properties = make_properties(logger, tmp_dir, {"iga.google.enabled": "true"},
									 env_namespace=PREFIX, validate=True)
	assert properties.get("iga.google.client_id") == "an-id"
	logger.info("test_required_if_triggered_by_local_and_satisfied_by_env_passes passed")


# --- the environment layer is validated too, which the file-level function cannot do -

def test_invalid_env_value_raises(logger, tmp_dir):
	# _apply_env_layer accepts this: the variable maps to a known key and is not empty.
	# Only spec validation on the resolved values catches it.
	with environment({PREFIX + "LOG_LEVEL": "verbose"}):
		message = expect_error(ValueError, "an environment override must be checked against @values",
							   lambda: make_properties(logger, tmp_dir, {}, env_namespace=PREFIX, validate=True))
	assert "log.level" in message, message
	logger.info("test_invalid_env_value_raises passed")


def test_valid_env_value_passes(logger, tmp_dir):
	with environment({PREFIX + "LOG_LEVEL": "TRACE"}):
		properties = make_properties(logger, tmp_dir, {}, env_namespace=PREFIX, validate=True)
	assert properties.get("log.level") == "TRACE"
	logger.info("test_valid_env_value_passes passed")


# --- each bad value points at the layer it came from ---------------------------------

def test_error_names_the_environment_variable(logger, tmp_dir):
	with environment({PREFIX + "LOG_LEVEL": "verbose"}):
		message = expect_error(ValueError, "the value is invalid",
							   lambda: make_properties(logger, tmp_dir, {}, env_namespace=PREFIX, validate=True))
	assert PREFIX + "LOG_LEVEL" in message, "the error must name the variable to fix: {}".format(message)
	logger.info("test_error_names_the_environment_variable passed")


def test_error_names_the_local_layer(logger, tmp_dir):
	message = expect_error(ValueError, "the value is invalid",
						   lambda: make_properties(logger, tmp_dir, {"log.level": "verbose"}, validate=True))
	assert "from local" in message, "the error must say which layer set it: {}".format(message)
	logger.info("test_error_names_the_local_layer passed")


def test_error_names_the_default_layer(logger, tmp_dir):
	placeholder_default = ANNOTATED_DEFAULT.replace("smtp.port=25", "smtp.port=CHANGEME")
	message = expect_error(ValueError, "the default value is invalid and nothing overrides it",
						   lambda: make_properties(logger, tmp_dir, {}, default_text=placeholder_default, validate=True))
	assert "from default" in message, "the error must say which layer set it: {}".format(message)
	logger.info("test_error_names_the_default_layer passed")


# --- the standalone function keeps working for files nothing is going to load --------

def test_standalone_accepts_a_valid_file(logger, tmp_dir):
	default_path, local_path = write_files(tmp_dir, ANNOTATED_DEFAULT, {"log.level": "DEBUG"})
	assert validate_properties_file(local_path, default_path, logger) is True
	logger.info("test_standalone_accepts_a_valid_file passed")


def test_standalone_rejects_an_invalid_file(logger, tmp_dir):
	default_path, local_path = write_files(tmp_dir, ANNOTATED_DEFAULT, {"log.level": "verbose", "log.levl": "x"})
	message = expect_error(ValueError, "the file has an invalid value and an unrecognized key",
						   lambda: validate_properties_file(local_path, default_path, logger))
	assert "log.level" in message and "log.levl" in message, message
	assert local_path in message, "the error must name the file that failed: {}".format(message)
	logger.info("test_standalone_rejects_an_invalid_file passed")


def test_standalone_message_has_no_layer_annotation(logger, tmp_dir):
	# Validating a file on its own has no layers to attribute values to, so the
	# wording stays exactly as it was before the shared core was extracted.
	default_path, local_path = write_files(tmp_dir, ANNOTATED_DEFAULT, {"log.level": "verbose"})
	message = expect_error(ValueError, "the value is invalid",
						   lambda: validate_properties_file(local_path, default_path, logger))
	assert "'verbose'" in message, message
	assert "(from" not in message, "there is no layer to name here: {}".format(message)
	logger.info("test_standalone_message_has_no_layer_annotation passed")


def test_standalone_ignores_the_environment(logger, tmp_dir):
	# The file-level function validates the file, not the process configuration.
	default_path, local_path = write_files(tmp_dir, ANNOTATED_DEFAULT, {"log.level": "DEBUG"})
	with environment({PREFIX + "LOG_LEVEL": "verbose"}):
		assert validate_properties_file(local_path, default_path, logger) is True
	logger.info("test_standalone_ignores_the_environment passed")


def run(logger):
	with tempfile.TemporaryDirectory() as tmp_dir:
		test_invalid_values_pass_without_the_flag(logger, tmp_dir)
		test_local_only_key_passes_without_the_flag(logger, tmp_dir)
		test_validate_is_keyword_only(logger, tmp_dir)
		test_valid_configuration_passes(logger, tmp_dir)
		test_defaults_alone_pass(logger, tmp_dir)
		test_enum_violation_raises(logger, tmp_dir)
		test_bool_violation_raises(logger, tmp_dir)
		test_int_violation_raises(logger, tmp_dir)
		test_required_blanked_by_local_raises(logger, tmp_dir)
		test_unknown_key_raises(logger, tmp_dir)
		test_every_violation_is_reported_at_once(logger, tmp_dir)
		test_default_placeholder_fixed_by_local_passes(logger, tmp_dir)
		test_required_if_triggered_by_local_and_unsatisfied_raises(logger, tmp_dir)
		test_required_if_triggered_by_local_and_satisfied_by_env_passes(logger, tmp_dir)
		test_invalid_env_value_raises(logger, tmp_dir)
		test_valid_env_value_passes(logger, tmp_dir)
		test_error_names_the_environment_variable(logger, tmp_dir)
		test_error_names_the_local_layer(logger, tmp_dir)
		test_error_names_the_default_layer(logger, tmp_dir)
		test_standalone_accepts_a_valid_file(logger, tmp_dir)
		test_standalone_rejects_an_invalid_file(logger, tmp_dir)
		test_standalone_message_has_no_layer_annotation(logger, tmp_dir)
		test_standalone_ignores_the_environment(logger, tmp_dir)


def main():
	logger = Logger(os.path.basename(__file__), "DEBUG", "sherpa_logger.log")
	logger.info("{} starting.".format(os.path.basename(__file__)))
	run(logger)
	logger.info("{} finished, all tests passed.".format(os.path.basename(__file__)))


if __name__ == "__main__":
	sys.exit(main())
