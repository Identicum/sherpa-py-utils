# sherpa-py-utils is available under the MIT License. https://github.com/Identicum/sherpa-py-utils/
# Copyright (c) 2024, Identicum - https://identicum.com/
#
# Author: Gustavo J Gallardo - ggallard@identicum.com
#

import ldap
import ldap.dn
import ldap.modlist as modlist
import time
from sherpa.utils.basics import Logger
from importlib.metadata import version


class LDAP(object):
	def __init__(self, ip_address, user_dn, user_password, logger, protocol="ldaps", port="636", iterations=10, interval=5, timeout=3, verify=False):
		logger.trace("Initializing LDAP. ip_address: {}, user_dn: {}, user_password: {}", ip_address, user_dn, user_password)
		self.protocol = protocol
		self._logger = logger
		self._logger.debug("LDAP version: " + version("sherpa-py-utils"))
		ldap_url = "{}://{}:{}".format(protocol, ip_address, port)
		for iteration in range(iterations):
			try:
				ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND) if verify and protocol == "ldaps" else ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
				ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
				ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, timeout)
				logger.info("Trying to connect to {}, iteration: {}", ldap_url, iteration+1)
				self._conn = ldap.initialize(ldap_url)
				self._conn.protocol_version = ldap.VERSION3
				logger.info("Binding using {}", user_dn)
				self._conn.simple_bind_s(user_dn, user_password)
				logger.debug("LDAP bind OK to ({}) with user: {}", ldap_url, user_dn)
				return
			except:
				logger.info("Waiting {} seconds.".format(interval))
				time.sleep(interval)
		logger.error("Failed to connect to LDAP {}.".format(protocol, ip_address, port))


	def get_objects(self, base_dn, filter="(objectclass=*)", attributes=["*"], scope=ldap.SCOPE_SUBTREE):
		self._logger.debug("Getting objects. base_dn: {}, filter: {}, attributes: {}.", base_dn, filter, attributes)
		result = self._conn.search_s(base_dn, scope, filter, attributes)
		for item in result:
			self._logger.trace("Found object: {}", item)
		return result


	def get_object(self, object_dn):
		self._logger.debug("Getting object: {}.", object_dn)
		query = "objectclass=*"
		result = self._conn.search_s(object_dn, ldap.SCOPE_BASE, query)
		for item in result:
			self._logger.debug("Found object: {}", item)
		return item


	def create_object(self, object_dn, object_attrs):
		self._logger.debug("Creating object: {}.", object_dn)
		addLdif = modlist.addModlist(object_attrs)
		self._logger.debug("Creating object: {} using ldif: {}", object_dn, addLdif)
		self._conn.add_s(object_dn, addLdif)
		self._logger.debug("Object added.")


	def create_ad_user(self, base_dn, username, password, upn, given_name, last_name):
		object_dn = "cn={},{}".format(username, base_dn)
		self._logger.debug("Creating user: {}.", object_dn)
		attrs = {}
		attrs['objectClass'] = ['user'.encode()]
		attrs['userAccountControl'] = ["512".encode()]
		attrs['sAMAccountName'] = [username.encode()]
		attrs['userPrincipalName'] = [upn.encode()]
		attrs['givenName'] = [given_name.encode()]
		attrs['sn'] = [last_name.encode()]
		self.create_object(object_dn, attrs)
		self.set_ad_password(object_dn, password)


	def set_ad_password(self, object_dn, password):
		self._logger.debug("Settind AD password on: {}.", object_dn)
		password_with_quotes = '"{}"'.format(password)
		encoded_password = password_with_quotes.encode('utf-16-le')
		self._logger.debug("Password: {}, password_with_quotes: {}, encoded_password: {},  object_dn: {}", password, password_with_quotes, encoded_password, object_dn)
		self._conn.modify_s(object_dn, [(ldap.MOD_REPLACE, 'unicodePwd',  [encoded_password])])
		self._logger.debug("Password set.")


	def create_ad_ou(self, base_dn, name):
		object_dn = "ou={},{}".format(name, base_dn)
		self._logger.debug("Creating OU: {}.", object_dn)
		attrs = {}
		attrs['objectClass'] = ['organizationalUnit'.encode()]
		self.create_object(object_dn, attrs)


	def create_ad_group(self, base_dn, name, members):
		object_dn = "cn={},{}".format(name, base_dn)
		self._logger.debug("Creating Group: {}.", object_dn)
		attrs = {}
		attrs['objectClass'] = ['group'.encode()]
		attrs['sAMAccountName'] = [name.encode()]
		if(len(members) > 0):
			attrs['member'] = members
		self.create_object(object_dn, attrs)
