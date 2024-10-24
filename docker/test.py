#!/usr/bin/env python3

import os
import sys

sys.path.insert(1, "../sherpa/")
from utils.basics import Logger
from utils.basics import Properties
from utils.ldap import LDAP;

def main():
	properties = Properties("default.properties", "default.properties")
	logger = Logger(os.path.basename(__file__), properties.get("log_level"), properties.get("log_file"))
	run(logger, properties)
	logger.info("{} finished.".format(os.path.basename(__file__)))


def run(logger, properties):
	logger.info("{} starting.".format(os.path.basename(__file__)))

	ip_address = "samba"
	base_dn = "dc=sherpa-demo,dc=com"
	admin_dn = "cn=administrator,cn=users,{}".format(base_dn)
	admin_password = "Sherpa.2024"
	ldap = LDAP(ip_address=ip_address, user_dn=admin_dn, user_password=admin_password, logger=logger)
	users_base_dn = "ou=sherpa_users,{}".format(base_dn)
	groups_base_dn = "ou=sherpa_groups,{}".format(base_dn)

	ldap.create_ad_ou(base_dn, "sherpa_users", True)
	ldap.create_ad_ou(base_dn, "sherpa_groups", True)
	group_members = []
	for i in range(100):
		ldap.create_ad_user(users_base_dn, f"testuser{i}", "testPassword.2024", f"testuser{i}@sherpa-demo.com", "Test", "User1", True)
		group_members.append((f"cn=testuser{i},{users_base_dn}").encode())
  
	ldap.create_ad_group(groups_base_dn, "testgroup", group_members, True)

	ldap.get_object(admin_dn)
	ldap.get_objects(users_base_dn, filter="(objectclass=user)", attributes=["cn","sn","givenName"], page_size=20)

if __name__ == "__main__":
	sys.exit(main())

