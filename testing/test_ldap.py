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


def create_ldap_objects(logger, properties, ldap, base_dn, users_base_dn, groups_base_dn):
	ldap.create_ad_ou(base_dn, "sherpa_users", ignore_if_exists=True)
	ldap.create_ad_ou(base_dn, "sherpa_groups", ignore_if_exists=True)
	group_members = []
	ldap.create_ad_user(users_base_dn, f"testuser000", "testPassword.2025", f"testuser000@sherpa-demo.com", "Test000", "User000", employee_id="000", title="title000", employee_type="contractor", ignore_if_exists=True)
	ldap.create_ad_user(users_base_dn, f"testuser001", "testPassword.2025", f"testuser001@sherpa-demo.com", "Test001", "User001", employee_id="001", department="department001", ignore_if_exists=True)
	for i in range(2):
		ldap.create_ad_user(users_base_dn, f"testuser{i}", "testPassword.2025", f"testuser{i}@sherpa-demo.com", "Test", "User1", ignore_if_exists=True)
		group_members.append((f"cn=testuser{i},{users_base_dn}").encode())
	ldap.create_ad_group(groups_base_dn, "testgroup1", group_members, ignore_if_exists=True)
	ldap.create_ad_group(groups_base_dn, "testgroup2", group_members, ignore_if_exists=True)


def run(logger, properties):
	logger.info("{} starting.".format(os.path.basename(__file__)))

	ip_address = "samba"
	base_dn = "dc=sherpa-demo,dc=com"
	admin_dn = "cn=administrator,cn=users,{}".format(base_dn)
	admin_password = "Sherpa.2025"
	ldap = LDAP(ip_address=ip_address, user_dn=admin_dn, user_password=admin_password, logger=logger)
	users_base_dn = "ou=sherpa_users,{}".format(base_dn)
	groups_base_dn = "ou=sherpa_groups,{}".format(base_dn)

	create_ldap_objects(logger, properties, ldap, base_dn, users_base_dn, groups_base_dn)

	for object in ldap.get_objects(users_base_dn, filter="(objectclass=user)", page_size=20):
		cvs_row = ldap.get_attributes_csv(object, attr_list=["cn","sn","givenName","employeeID","title", "employeeType", "memberOf", "department"], multivalue_separator="##")
		logger.info("CSV row: {}", cvs_row)
	ldap.get_object("ou=sherpa_groups,dc=sherpa-demo,dc=com")


if __name__ == "__main__":
	sys.exit(main())

