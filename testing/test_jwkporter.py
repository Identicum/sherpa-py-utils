#!/usr/bin/env python3

import argparse
from datetime import datetime
import json
import os
import sys
import base64
import requests
import time

sys.path.insert(1, "../")

from sherpa.utils.clients import OIDCClient
from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger

class JWKPorter:
	def __init__(self, logger, jwkporter_base_url, idp_url):
		self.logger = logger
		self._oidc_client = None
		self.jwkporter_base_url = jwkporter_base_url
		self.idp_url = idp_url

	@property
	def oidc_client(self):
		if self._oidc_client is None:
			self.logger.debug("Creating an OIDC Client for connections to IdP: {}".format(self.idp_url))
			self._oidc_client = OIDCClient(self.idp_url,self.logger, True)
		return self._oidc_client

	def _obtain_access_token(self, client_id, client_secret):
		client_id = client_id
		client_secret = client_secret
		credentials = f"{client_id}:{client_secret}".encode()
		b64_credentials = base64.b64encode(credentials).decode()
		credentials = self.oidc_client.do_client_credentials(b64_credentials, scope="openid jwksporter:sign jwksporter:crud")
		access_token = self.oidc_client.extract_access_token(credentials)
		return access_token

	def sign(self, client_id, client_secret, exp, features, customer, product, kid):
		self.logger.debug("Running method to sign JWT against JWK with public key {}".format("8388bb6b-4d8e-4be3-a5d4-080523a75e9b"))
		access_token = self._obtain_access_token(client_id, client_secret)
		endpoint_url = self.jwkporter_base_url + '/token/sign'
		iat = int(time.time())

		try:
			exp = int(datetime.strptime(exp, "%Y%m%d").timestamp())
		except ValueError:
			raise ValueError("Invalid expiration format. Please use YYYYMMDD.")

		features = [feature.strip() for feature in features.split(",")]
		if not features:
			raise ValueError("Features list cannot be empty.")
		payload = json.dumps({
			"kid": kid,
			"payload": {
				"iat": iat,
				"exp": exp,
				"customer": customer,
				"product": product,
				"features": features
			}
		})
		headers = {
			"Authorization": "Bearer {}".format(access_token),
			"Content-Type": "application/json"
		}
		self.logger.debug("Calling url: {} with headers: {} and payload: {}", endpoint_url, headers, payload)
		response = requests.post(url=endpoint_url, headers=headers, data=payload)
		if response.status_code == 200:
			self.logger.debug("signed_payload: {}", response.content)
			return response.content
		else:
			self.logger.debug(response)
			raise Exception("Failed to sign payload: {} {}".format(response.status_code, response.text))

	def create(self, client_id, client_secret):
		self.logger.debug("Creating a JWK Key in JWKPortainer instance")
		access_token = self._obtain_access_token(client_id, client_secret)
		endpoint_url = self.jwkporter_base_url + '/jwks/manage'
		headers = {
			"Authorization": "Bearer {}".format(access_token),
			"Content-Type": "application/json"
		}
		response = requests.post(url=endpoint_url, headers=headers)
		if response.status_code == 200:
			self.logger.debug("jwk: {}", response.content)
			return response.content
		else:
			self.logger.debug(response)
			raise Exception("Failed to create a JWK: {} {}".format(response.status_code, response.text))

	def verify(self):
		logger.debug("Verify: {}", payload)



def main(arguments):
	properties = Properties("default.properties", "local.properties")
	logger = Logger(os.path.basename(__file__), properties.get("log_level"), properties.get("log_file"))
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('product', type=str, help="Product (IRM, IAM-CRUD)")
	parser.add_argument('customer', type=str, help="Customer name")
	parser.add_argument('exp', type=str, help="Expiration date (YYYYMMDD)")
	parser.add_argument('features', type=str, help="Enabled features (comma-separated)")

	args = parser.parse_args(arguments)
	run(logger, properties, args)
	logger.info("{} finished.".format(os.path.basename(__file__)))

def run(logger, properties, args):
	logger.info("{} starting.".format(os.path.basename(__file__)))
	exp = args.exp
	features = args.features
	customer = args.customer
	product = args.product
	logger.debug("Obtaining client_id, client_secret, jwkporter base url and idp base url")
	client_id = properties.get("jwkporter_client_id")
	client_secret = properties.get("jwkporter_client_secret")
	jwkporter_base_url = properties.get("jwkporter_base_url")
	idp_url = properties.get("idp_url")

	logger.debug("Creating JWKPorter instance")
	jwkporter = JWKPorter(logger, jwkporter_base_url, idp_url)

	jwk = jwkporter.create(client_id, client_secret)
	data = json.loads(jwk.decode('utf-8'))
	kid = data.get("kid")

	jwkporter.sign(client_id, client_secret, exp, features,customer, product, kid)

	logger.debug("run finished successfully")

if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))