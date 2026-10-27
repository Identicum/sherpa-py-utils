#!/usr/bin/env python3
#
# Executable spec for get_property_specs: the metadata exposed to tools that build on
# the annotated default.properties (e.g. a configuration UI) rather than validate it.
#

import os
import sys
import tempfile

sys.path.insert(1, "../")
from sherpa.utils.basics import Logger
from sherpa.utils.basics import get_property_errors
from sherpa.utils.basics import get_property_specs
from sherpa.utils.basics import read_properties_file
from sherpa.utils.basics import validate_properties_file


ANNOTATED_DEFAULT = """
# @section Core
# @description Initial master password set for the deployment
# @type string
# @required true
# @default Sherpa.2026
# @scope environment
# @secret true
master_password=Sherpa.2026

# @section Core
# @description Display name for the organization
# @type string
# @required true
organization_name=Sherpa

# @section IGA - Active Directory
# @type bool
# @scope customer
iga.ad.enabled=false

# @section IGA - Active Directory
# @type string
# @scope Environment
# @required_if iga.ad.enabled=true
iga.ad.hostname=

untagged=value
"""


def write_default(tmp_dir, default_text=ANNOTATED_DEFAULT):
	default_path = os.path.join(tmp_dir, "default.properties")
	with open(default_path, "wt") as f:
		f.write(default_text)
	return default_path


def test_keys_keep_file_order(logger, tmp_dir):
	specs = get_property_specs(write_default(tmp_dir))
	assert list(specs) == ["master_password", "organization_name", "iga.ad.enabled", "iga.ad.hostname", "untagged"], list(specs)
	logger.info("test_keys_keep_file_order passed")


def test_descriptive_tags_are_exposed(logger, tmp_dir):
	spec = get_property_specs(write_default(tmp_dir))["master_password"]
	assert spec["section"] == "Core", spec
	assert spec["description"] == "Initial master password set for the deployment", spec
	assert spec["default"] == "Sherpa.2026", spec
	logger.info("test_descriptive_tags_are_exposed passed")


def test_absent_descriptive_tags_are_none(logger, tmp_dir):
	# organization_name has a value but no @default tag: the tag is what is reported,
	# not the value, so a UI can tell "no default declared" apart from "empty default".
	specs = get_property_specs(write_default(tmp_dir))
	assert specs["organization_name"]["default"] is None, specs["organization_name"]
	assert specs["iga.ad.enabled"]["description"] is None, specs["iga.ad.enabled"]
	assert specs["untagged"]["section"] is None, specs["untagged"]
	logger.info("test_absent_descriptive_tags_are_none passed")


def test_scope_defaults_to_customer(logger, tmp_dir):
	specs = get_property_specs(write_default(tmp_dir))
	assert specs["organization_name"]["scope"] == "customer", specs["organization_name"]
	assert specs["iga.ad.enabled"]["scope"] == "customer", specs["iga.ad.enabled"]
	assert specs["master_password"]["scope"] == "environment", specs["master_password"]
	logger.info("test_scope_defaults_to_customer passed")


def test_scope_is_case_insensitive(logger, tmp_dir):
	spec = get_property_specs(write_default(tmp_dir))["iga.ad.hostname"]
	assert spec["scope"] == "environment", spec
	logger.info("test_scope_is_case_insensitive passed")


def test_secret_only_when_tagged_true(logger, tmp_dir):
	specs = get_property_specs(write_default(tmp_dir))
	assert specs["master_password"]["secret"] is True, specs["master_password"]
	assert specs["organization_name"]["secret"] is False, specs["organization_name"]
	logger.info("test_secret_only_when_tagged_true passed")


def test_validation_specs_are_unchanged(logger, tmp_dir):
	specs = get_property_specs(write_default(tmp_dir))
	assert specs["master_password"]["required"] is True, specs["master_password"]
	assert specs["iga.ad.hostname"]["required_if"] == [[("iga.ad.enabled", "true")]], specs["iga.ad.hostname"]
	logger.info("test_validation_specs_are_unchanged passed")


def test_new_tags_do_not_affect_validation(logger, tmp_dir):
	default_path = write_default(tmp_dir)
	local_path = os.path.join(tmp_dir, "local.properties")
	with open(local_path, "wt") as f:
		f.write("iga.ad.enabled=true\niga.ad.hostname=dc1\n")
	assert validate_properties_file(local_path, default_path, logger) is True
	logger.info("test_new_tags_do_not_affect_validation passed")


def test_read_properties_file_keeps_values_and_order(logger, tmp_dir):
	values = read_properties_file(write_default(tmp_dir))
	assert list(values) == ["master_password", "organization_name", "iga.ad.enabled", "iga.ad.hostname", "untagged"], list(values)
	assert values["master_password"] == "Sherpa.2026" and values["iga.ad.hostname"] == "", values
	logger.info("test_read_properties_file_keeps_values_and_order passed")


def test_property_errors_are_returned_not_raised(logger, tmp_dir):
	default_path = write_default(tmp_dir)
	specs = get_property_specs(default_path)
	effective = {**read_properties_file(default_path), "iga.ad.enabled": "true", "organization_name": ""}
	errors = get_property_errors(specs, effective)
	assert len(errors) == 2, errors
	assert sorted(error.split(" ", 1)[0] for error in errors) == ["iga.ad.hostname", "organization_name"], errors
	logger.info("test_property_errors_are_returned_not_raised passed")


def test_property_errors_empty_when_valid(logger, tmp_dir):
	default_path = write_default(tmp_dir)
	effective = {**read_properties_file(default_path), "iga.ad.enabled": "true", "iga.ad.hostname": "dc1"}
	assert get_property_errors(get_property_specs(default_path), effective) == []
	logger.info("test_property_errors_empty_when_valid passed")


def run(logger):
	with tempfile.TemporaryDirectory() as tmp_dir:
		test_keys_keep_file_order(logger, tmp_dir)
		test_descriptive_tags_are_exposed(logger, tmp_dir)
		test_absent_descriptive_tags_are_none(logger, tmp_dir)
		test_scope_defaults_to_customer(logger, tmp_dir)
		test_scope_is_case_insensitive(logger, tmp_dir)
		test_secret_only_when_tagged_true(logger, tmp_dir)
		test_validation_specs_are_unchanged(logger, tmp_dir)
		test_new_tags_do_not_affect_validation(logger, tmp_dir)
		test_read_properties_file_keeps_values_and_order(logger, tmp_dir)
		test_property_errors_are_returned_not_raised(logger, tmp_dir)
		test_property_errors_empty_when_valid(logger, tmp_dir)


def main():
	logger = Logger(os.path.basename(__file__), "DEBUG", "sherpa_logger.log")
	logger.info("{} starting.".format(os.path.basename(__file__)))
	run(logger)
	logger.info("{} finished, all tests passed.".format(os.path.basename(__file__)))


if __name__ == "__main__":
	sys.exit(main())
