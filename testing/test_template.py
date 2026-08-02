#!/usr/bin/env python3

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(1, "../")
from sherpa.utils.basics import Logger
from sherpa.utils.basics import Properties
from sherpa.utils.basics import Template


def make_properties(tmp_dir, entries):
	default_path = os.path.join(tmp_dir, "default.properties")
	local_path = os.path.join(tmp_dir, "local.properties")
	with open(default_path, "wt") as f:
		f.write("")
	with open(local_path, "wt") as f:
		for key, value in entries.items():
			f.write("{}={}\n".format(key, value))
	return Properties(local_path, default_path, "$(", ")")


def test_simple_true_if(logger, tmp_dir):
	properties = make_properties(tmp_dir, {"google.enabled": "true"})
	template = Template(properties, logger)
	content = "before\n<!-- IF google.enabled -->kept\n<!-- ENDIF -->after"
	rendered = template.render(content)
	assert rendered == "before\nkept\nafter", "true IF should keep its block: {}".format(repr(rendered))
	logger.info("test_simple_true_if passed")


def test_simple_false_if(logger, tmp_dir):
	properties = make_properties(tmp_dir, {"google.enabled": "false"})
	template = Template(properties, logger)
	content = "before\n<!-- IF google.enabled -->dropped\n<!-- ENDIF -->after"
	rendered = template.render(content)
	assert rendered == "before\nafter", "false IF should drop its block: {}".format(repr(rendered))
	logger.info("test_simple_false_if passed")


def test_negation(logger, tmp_dir):
	properties = make_properties(tmp_dir, {"google.enabled": "false"})
	template = Template(properties, logger)
	assert template.render("<!-- IF !google.enabled -->kept<!-- ENDIF -->") == "kept"
	assert template.render("<!-- IF not google.enabled -->kept<!-- ENDIF -->") == "kept"
	logger.info("test_negation passed")


def test_equals_not_equals(logger, tmp_dir):
	properties = make_properties(tmp_dir, {"google.groups": "XXX"})
	template = Template(properties, logger)
	content_eq = '<!-- IF google.groups == "XXX" -->match<!-- ENDIF -->'
	content_neq = '<!-- IF google.groups != "YYY" -->nomatch<!-- ENDIF -->'
	assert template.render(content_eq) == "match"
	assert template.render(content_neq) == "nomatch"
	logger.info("test_equals_not_equals passed")


def test_nesting(logger, tmp_dir):
	properties = make_properties(tmp_dir, {"outer": "true", "inner": "false"})
	template = Template(properties, logger)
	content = "<!-- IF outer -->A<!-- IF inner -->B<!-- ENDIF -->C<!-- ENDIF -->"
	rendered = template.render(content)
	assert rendered == "AC", "nested false IF should drop only its own block: {}".format(repr(rendered))
	logger.info("test_nesting passed")


def test_unmatched_if_raises(logger, tmp_dir):
	properties = make_properties(tmp_dir, {})
	template = Template(properties, logger)
	try:
		template.render("<!-- IF something -->unterminated")
		raise AssertionError("expected ValueError for unmatched IF")
	except ValueError:
		logger.info("test_unmatched_if_raises passed")


def test_unmatched_endif_raises(logger, tmp_dir):
	properties = make_properties(tmp_dir, {})
	template = Template(properties, logger)
	try:
		template.render("stray<!-- ENDIF -->")
		raise AssertionError("expected ValueError for unmatched ENDIF")
	except ValueError:
		logger.info("test_unmatched_endif_raises passed")


def test_process_file_discard_empty(logger, tmp_dir):
	properties = make_properties(tmp_dir, {"feature.enabled": "false"})
	template = Template(properties, logger)
	input_path = Path(tmp_dir) / "input.xml"
	input_path.write_text("<!-- IF feature.enabled -->\n<content/>\n<!-- ENDIF -->")

	discarded_output = Path(tmp_dir) / "out_discard" / "input.xml"
	result = template.process_file(input_path, discarded_output, discard_empty_file=True)
	assert result is None, "fully-excluded file should be discarded"
	assert not discarded_output.exists(), "discarded file must not be written"

	kept_output = Path(tmp_dir) / "out_keep" / "input.xml"
	result = template.process_file(input_path, kept_output, discard_empty_file=False)
	assert result == kept_output
	assert kept_output.exists() and kept_output.read_text() == "", "discard_empty_file=False must still write blank content"
	logger.info("test_process_file_discard_empty passed")


def test_process_folder_mirrors_structure(logger, tmp_dir):
	properties = make_properties(tmp_dir, {"feature.enabled": "true", "other.enabled": "false"})
	template = Template(properties, logger)

	source_dir = Path(tmp_dir) / "source"
	(source_dir / "sub").mkdir(parents=True)
	(source_dir / "kept.xml").write_text("<!-- IF feature.enabled -->kept<!-- ENDIF -->")
	(source_dir / "sub" / "dropped.xml").write_text("<!-- IF other.enabled -->dropped<!-- ENDIF -->")

	dest_dir = Path(tmp_dir) / "dest"
	written = template.process_folder(source_dir, dest_dir, discard_empty_file=True)

	assert written == [dest_dir / "kept.xml"], "unexpected files written: {}".format(written)
	assert (dest_dir / "kept.xml").read_text() == "kept"
	assert not (dest_dir / "sub").exists(), "no subfolder should be created for a fully-excluded file"
	logger.info("test_process_folder_mirrors_structure passed")


def test_custom_line_comment_delimiter(logger, tmp_dir):
	properties = make_properties(tmp_dir, {"tf.enabled": "true"})
	template = Template(properties, logger, comment_start="#", comment_end="")
	content = "before\n# IF tf.enabled\nresource kept {}\n# ENDIF\nafter"
	rendered = template.render(content)
	assert rendered == "before\nresource kept {}\nafter", "custom line-comment delimiter should work: {}".format(repr(rendered))
	logger.info("test_custom_line_comment_delimiter passed")


def run(logger):
	with tempfile.TemporaryDirectory() as tmp_dir:
		test_simple_true_if(logger, tmp_dir)
		test_simple_false_if(logger, tmp_dir)
		test_negation(logger, tmp_dir)
		test_equals_not_equals(logger, tmp_dir)
		test_nesting(logger, tmp_dir)
		test_unmatched_if_raises(logger, tmp_dir)
		test_unmatched_endif_raises(logger, tmp_dir)
		test_process_file_discard_empty(logger, tmp_dir)
		test_process_folder_mirrors_structure(logger, tmp_dir)
		test_custom_line_comment_delimiter(logger, tmp_dir)


def main():
	logger = Logger(os.path.basename(__file__), "DEBUG", "sherpa_logger.log")
	logger.info("{} starting.".format(os.path.basename(__file__)))
	run(logger)
	logger.info("{} finished, all tests passed.".format(os.path.basename(__file__)))


if __name__ == "__main__":
	sys.exit(main())
