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
	def __init__(self, properties, logger, oidc_client: OIDCClient, jwkporter_base_url: str):
		self.oidc_client = oidc_client
		self.properties = properties
		self.logger = logger
		self.jwkporter_base_url = jwkporter_base_url

	def _obtain_access_token(self):
		client_id = self.properties.get("jwkporter_client_id")
		client_secret = self.properties.get("jwkporter_client_secret")
		credentials = f"{client_id}:{client_secret}".encode()
		b64_credentials = base64.b64encode(credentials).decode()
		credentials = self.oidc_client.do_client_credentials(b64_credentials, scope="openid jwksporter:sign jwksporter:crud")
		access_token = self.oidc_client.extract_access_token(credentials)
		return access_token

	def sign(self, args):
		access_token = self._obtain_access_token()
		endpoint_url = self.jwkporter_base_url + '/token/sign'
		iat = int(time.time())

		try:
			exp = int(datetime.strptime(args.exp, "%Y%m%d").timestamp())
		except ValueError:
			raise ValueError("Invalid expiration format. Please use YYYYMMDD.")

		features = [feature.strip() for feature in args.features.split(",")]
		if not features:
			raise ValueError("Features list cannot be empty.")
		payload = json.dumps({
			"kid": "8388bb6b-4d8e-4be3-a5d4-080523a75e9b",
			"payload": {
				"iat": iat,
				"exp": exp,
				"customer": args.customer,
				"product": args.product,
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
		else:
			self.logger.debug(response)
			raise Exception("Failed to sign payload: {} {}".format(response.status_code, response.text))

	def create(self, logger, properties, payload):
		logger.debug("Payload: {}", payload)

	def verify(self, logger, properties, payload):
		logger.debug("Payload: {}", payload)



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
	logger.debug("Obtaining idp url and jwkporter url from properties")
	idp_url = properties.get("idp_url")
	jwkporter_url = properties.get("jwkporter_base_url")
	logger.info("Obtained {} as idp_url and {} as jwkporter_base_url".format(idp_url, jwkporter_url))

	logger.debug("Creating OIDCClient instance")
	oidc = OIDCClient(idp_url, logger, True)
	logger.debug("Creating JWKPorter instance")
	jwkporter = JWKPorter(properties=properties, logger=logger, oidc_client=oidc, jwkporter_base_url=jwkporter_url)
	logger.debug("Running JWKPorter sign method")
	jwkporter.sign(args)

	logger.debug("run finished successfully")

if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))