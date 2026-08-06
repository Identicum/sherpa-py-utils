#!/usr/bin/env python3
#
# Executable spec for the third Properties layer (default < local < environment).
# These tests fail until the layer is implemented in sherpa/utils/basics.py
#

import contextlib
import os
import sys
import tempfile

sys.path.insert(1, "../")
from sherpa.utils.basics import Logger
from sherpa.utils.basics import Properties


# Tests use their own namespace: SHERPA_ would make them depend on whatever the
# developer happens to have exported in their shell.
PREFIX = "TESTPFX_"

DEFAULT_ENTRIES = {
	"log.level": "INFO",
	"master_password": "fromdefault",
	"iga.ad.1.bind_dn": "cn=default",
	"path": "/opt/app",
}
LOCAL_ENTRIES = {
	"log.level": "DEBUG",
}


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


def make_properties(logger, tmp_dir, default_entries=None, local_entries=None, **kwargs):
	default_path = os.path.join(tmp_dir, "default.properties")
	local_path = os.path.join(tmp_dir, "local.properties")
	if default_entries is None:
		default_entries = DEFAULT_ENTRIES
	if local_entries is None:
		local_entries = LOCAL_ENTRIES
	for path, entries in ((default_path, default_entries), (local_path, local_entries)):
		with open(path, "wt") as f:
			for key, value in entries.items():
				f.write("{}={}\n".format(key, value))
	return Properties(local_path, default_path, "$(", ")", logger, **kwargs)


def expect_error(error_type, reason, callable_obj):
	try:
		callable_obj()
	except error_type:
		return
	raise AssertionError("expected {} because {}".format(error_type.__name__, reason))


# --- layer disabled / precedence ----------------------------------------------------

def test_env_layer_disabled_when_no_namespace(logger, tmp_dir):
	with environment({PREFIX + "LOG_LEVEL": "TRACE"}):
		properties = make_properties(logger, tmp_dir)
	assert properties.get("log.level") == "DEBUG", "without env_namespace the environment must be ignored entirely"
	logger.info("test_env_layer_disabled_when_no_namespace passed")


def test_env_wins_over_local_and_default(logger, tmp_dir):
	with environment({PREFIX + "LOG_LEVEL": "TRACE"}):
		properties = make_properties(logger, tmp_dir, env_namespace=PREFIX)
	assert properties.get("log.level") == "TRACE", "the environment must override the local file"
	assert properties.get("master_password") == "fromdefault", "a key with no variable keeps its file value"
	logger.info("test_env_wins_over_local_and_default passed")


# --- an empty variable is an error --------------------------------------------------

def test_empty_env_var_raises(logger, tmp_dir):
	with environment({PREFIX + "LOG_LEVEL": ""}):
		expect_error(ValueError, "a variable that is set but empty is an error",
					 lambda: make_properties(logger, tmp_dir, env_namespace=PREFIX))
	logger.info("test_empty_env_var_raises passed")


# --- an unrecognized variable is an error -------------------------------------------

def test_unknown_prefixed_var_raises(logger, tmp_dir):
	with environment({PREFIX + "DOES_NOT_EXIST": "x"}):
		expect_error(ValueError, "the variable matches no property in the catalog",
					 lambda: make_properties(logger, tmp_dir, env_namespace=PREFIX))
	logger.info("test_unknown_prefixed_var_raises passed")


def test_lowercase_var_name_is_unknown(logger, tmp_dir):
	# The mapping is exact: only the uppercase form is valid.
	with environment({PREFIX + "log_level": "TRACE"}):
		expect_error(ValueError, "a lowercase name does not match and must be reported as unknown",
					 lambda: make_properties(logger, tmp_dir, env_namespace=PREFIX))
	logger.info("test_lowercase_var_name_is_unknown passed")


def test_unprefixed_vars_are_ignored(logger, tmp_dir):
	# PATH and HOME are already set in any container.
	with environment({"OTHER_LOG_LEVEL": "TRACE", "LOG_LEVEL": "TRACE"}):
		properties = make_properties(logger, tmp_dir, env_namespace=PREFIX)
	assert properties.get("log.level") == "DEBUG", "variables without the namespace must be neither applied nor reported"
	logger.info("test_unprefixed_vars_are_ignored passed")


# --- canonical mapping and collisions -----------------------------------------------

def test_key_to_var_name_mapping(logger, tmp_dir):
	with environment({
		PREFIX + "IGA_AD_1_BIND_DN": "cn=fromenv",   # dots and digits become underscores
		PREFIX + "MASTER_PASSWORD": "s3cret",        # the key already held an underscore
	}):
		properties = make_properties(logger, tmp_dir, env_namespace=PREFIX)
	assert properties.get("iga.ad.1.bind_dn") == "cn=fromenv"
	assert properties.get("master_password") == "s3cret"
	logger.info("test_key_to_var_name_mapping passed")


def test_colliding_keys_raise_at_construction(logger, tmp_dir):
	# smtp.host and smtp_host both map onto TESTPFX_SMTP_HOST
	colliding = {"smtp.host": "a", "smtp_host": "b"}
	expect_error(ValueError, "two keys mapping onto the same variable name are ambiguous",
				 lambda: make_properties(logger, tmp_dir, default_entries=colliding, local_entries={}, env_namespace=PREFIX))
	logger.info("test_colliding_keys_raise_at_construction passed")


def test_colliding_keys_are_harmless_without_namespace(logger, tmp_dir):
	colliding = {"smtp.host": "a", "smtp_host": "b"}
	properties = make_properties(logger, tmp_dir, default_entries=colliding, local_entries={})
	assert properties.get("smtp.host") == "a" and properties.get("smtp_host") == "b", \
		"with the layer disabled the collision does not exist and must not get in the way"
	logger.info("test_colliding_keys_are_harmless_without_namespace passed")


# --- the namespace shields properties from OS variables -----------------------------

def test_os_variable_does_not_poison_property(logger, tmp_dir):
	# 'path' is a valid property name and PATH is set in any container
	properties = make_properties(logger, tmp_dir, env_namespace=PREFIX)
	assert properties.get("path") == "/opt/app", "the OS PATH must not override the 'path' property"
	logger.info("test_os_variable_does_not_poison_property passed")


# --- the environment is a snapshot taken at construction ----------------------------

def test_environment_is_read_once_at_construction(logger, tmp_dir):
	properties = make_properties(logger, tmp_dir, env_namespace=PREFIX)
	with environment({PREFIX + "LOG_LEVEL": "TRACE"}):
		assert properties.get("log.level") == "DEBUG", "changing the environment after construction must not alter the instance"
	logger.info("test_environment_is_read_once_at_construction passed")


# --- provenance ---------------------------------------------------------------------

def test_get_source(logger, tmp_dir):
	with environment({PREFIX + "MASTER_PASSWORD": "s3cret"}):
		properties = make_properties(logger, tmp_dir, env_namespace=PREFIX)
	assert properties.get_source("iga.ad.1.bind_dn") == "default"
	assert properties.get_source("log.level") == "local"
	assert properties.get_source("master_password") == PREFIX + "MASTER_PASSWORD"
	logger.info("test_get_source passed")


# --- new parameters are keyword-only ------------------------------------------------

def test_env_namespace_is_keyword_only(logger, tmp_dir):
	default_path = os.path.join(tmp_dir, "default.properties")
	local_path = os.path.join(tmp_dir, "local.properties")
	expect_error(TypeError, "env_namespace must not be accepted positionally",
				 lambda: Properties(local_path, default_path, "$(", ")", logger, PREFIX))
	logger.info("test_env_namespace_is_keyword_only passed")


# --- values are taken verbatim ------------------------------------------------------

def test_value_is_passed_verbatim(logger, tmp_dir):
	raw = '  with spaces, = , # and "quotes"  '
	with environment({PREFIX + "MASTER_PASSWORD": raw}):
		properties = make_properties(logger, tmp_dir, env_namespace=PREFIX)
	assert properties.get("master_password") == raw, \
		"an environment value is neither trimmed nor unquoted: {}".format(repr(properties.get("master_password")))
	logger.info("test_value_is_passed_verbatim passed")


def run(logger):
	with tempfile.TemporaryDirectory() as tmp_dir:
		test_env_layer_disabled_when_no_namespace(logger, tmp_dir)
		test_env_wins_over_local_and_default(logger, tmp_dir)
		test_empty_env_var_raises(logger, tmp_dir)
		test_unknown_prefixed_var_raises(logger, tmp_dir)
		test_lowercase_var_name_is_unknown(logger, tmp_dir)
		test_unprefixed_vars_are_ignored(logger, tmp_dir)
		test_key_to_var_name_mapping(logger, tmp_dir)
		test_colliding_keys_raise_at_construction(logger, tmp_dir)
		test_colliding_keys_are_harmless_without_namespace(logger, tmp_dir)
		test_os_variable_does_not_poison_property(logger, tmp_dir)
		test_environment_is_read_once_at_construction(logger, tmp_dir)
		test_get_source(logger, tmp_dir)
		test_env_namespace_is_keyword_only(logger, tmp_dir)
		test_value_is_passed_verbatim(logger, tmp_dir)


def main():
	logger = Logger(os.path.basename(__file__), "DEBUG", "sherpa_logger.log")
	logger.info("{} starting.".format(os.path.basename(__file__)))
	run(logger)
	logger.info("{} finished, all tests passed.".format(os.path.basename(__file__)))


if __name__ == "__main__":
	sys.exit(main())
