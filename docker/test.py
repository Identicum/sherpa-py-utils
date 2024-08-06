#!/usr/bin/env python3

import os
import shutil
import sys

from sherpa.utils.basics import Logger
from sherpa.utils.basics import Properties
from sherpa.utils.ldap import LDAP;

def main():
	properties = Properties("default.properties", "default.properties")
	logger = Logger(os.path.basename(__file__), properties.get("log_level"), properties.get("log_file"))
	run(logger, properties)
	logger.info("{} finished.".format(os.path.basename(__file__)))


def run(logger, properties):
	logger.info("{} starting.".format(os.path.basename(__file__)))

	ip_address = "samba"
	base_dn = "dc=sherpa-demo,dc=com"
	user_dn = "cn=administrator,cn=users,{}".format(base_dn)
	user_password = "Sherpa.2024"
	ldap = LDAP(ip_address=ip_address, user_dn=user_dn, user_password=user_password, logger=logger)
	users_base_dn = "ou=sherpa_users,{}".format(base_dn)
	groups_base_dn = "ou=sherpa_groups,{}".format(base_dn)

	ldap.create_ad_ou(base_dn, "sherpa_users")
	ldap.create_ad_ou(base_dn, "sherpa_groups")
	ldap.create_ad_user(users_base_dn, "testuser1", "testPassword.2024", "testuser1@sherpa-demo.com", "Test", "User1")
	ldap.create_ad_user(users_base_dn, "testuser2", "testPassword.2024", "testuser2@sherpa-demo.com", "Test", "User2")
	group_members = []
	group_members.append(("cn=testuser1,{}".format(users_base_dn)).encode())
	group_members.append(("cn=testuser2,{}".format(users_base_dn)).encode())
	ldap.create_ad_group(groups_base_dn, "testgroup", group_members)


if __name__ == "__main__":
	sys.exit(main())

