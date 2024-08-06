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
	user_dn = "cn=administrator,cn=users,dc=sherpa-demo,dc=com"
	user_password = "Sherpa.2024"
	ldap = LDAP(ip_address=ip_address, user_dn=user_dn, user_password=user_password, logger=logger)

	ldap.create_ad_ou("dc=sherpa-demo,dc=com", "meta")
	ldap.create_ad_ou("ou=meta,dc=sherpa-demo,dc=com", "users")
	ldap.create_ad_ou("ou=meta,dc=sherpa-demo,dc=com", "groups")

	ldap.create_ad_user("ou=users,ou=meta,dc=sherpa-demo,dc=com", "testuser", "testPassword.2024", "testuser@sherpa-demo.com", "Test", "User")


if __name__ == "__main__":
	sys.exit(main())

