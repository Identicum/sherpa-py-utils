#!/usr/bin/env python3

import os
import shutil
import sys

sys.path.insert(1, "../")
from sherpa.utils.basics import Logger
from sherpa.utils.basics import Properties
from sherpa.utils.ldap import LDAP;


def main():
	properties = Properties("default.properties", "local.properties", "$(", ")")
	logger = Logger(os.path.basename(__file__), properties.get("log_level"), properties.get("log_file"))
	run(logger, properties)
	logger.info("{} finished.".format(os.path.basename(__file__)))


def run(logger, properties):
	logger.info("{} starting.".format(os.path.basename(__file__)))

	# Test variables replacement
	origin_file_path = "replace.xml"
	with open(origin_file_path, "r") as file_object:
		origin_data = file_object.read()
	logger.debug("origin_data: {}.", origin_data)
	temp_file_path = "/tmp/replace.tmp"
	shutil.copyfile(origin_file_path, temp_file_path)
	properties.replace(temp_file_path)
	with open(temp_file_path, "r") as file_object:
		replaced_data = file_object.read()
	logger.debug("replaced_data: {}.", replaced_data)

	# Test LDAP
	ip_address = "samba"
	base_dn = "dc=sherpa-demo,dc=com"
	admin_dn = "cn=administrator,cn=users,{}".format(base_dn)
	admin_password = "Sherpa.2024"
	ldap = LDAP(ip_address=ip_address, user_dn=admin_dn, user_password=admin_password, logger=logger)
	users_base_dn = "ou=sherpa_users,{}".format(base_dn)
	groups_base_dn = "ou=sherpa_groups,{}".format(base_dn)

	ldap.create_ad_ou(base_dn, "sherpa_users", ignore_if_exists=True)
	ldap.create_ad_ou(base_dn, "sherpa_groups", ignore_if_exists=True)
	group_members = []
	ldap.create_ad_user(users_base_dn, f"testuser000", "testPassword.2024", f"testuser000@sherpa-demo.com", "Test000", "User000", employee_id="000", ignore_if_exists=True)
	for i in range(10):
		ldap.create_ad_user(users_base_dn, f"testuser{i}", "testPassword.2024", f"testuser{i}@sherpa-demo.com", "Test", "User1", ignore_if_exists=True)
		group_members.append((f"cn=testuser{i},{users_base_dn}").encode())
	ldap.create_ad_group(groups_base_dn, "testgroup", group_members, ignore_if_exists=True)
	ldap.get_object(admin_dn)
	for user in ldap.get_objects(users_base_dn, filter="(objectclass=user)", attributes=["cn","sn","givenName","employeeID"], page_size=20):
		logger.debug("user_found: {}.", user)


if __name__ == "__main__":
	sys.exit(main())

