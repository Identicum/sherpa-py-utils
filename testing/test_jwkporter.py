#!/usr/bin/env python3

import argparse
import json
import os
import sys

sys.path.insert(1, "../")

from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger
from sherpa.utils.jwkporter import JWKPorter
from sherpa.utils.license import build_license_json

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
	logger.debug("Obtaining client_id, client_secret, jwkporter base url and idp base url from properties")
	client_id = properties.get("jwkporter_client_id")
	client_secret = properties.get("jwkporter_client_secret")
	jwkporter_base_url = properties.get("jwkporter_base_url")
	idp_url = properties.get("idp_url")

	logger.debug("Creating JWKPorter instance")
	jwkporter = JWKPorter(logger, jwkporter_base_url, idp_url, client_id, client_secret)

	try:
		response = jwkporter.create_key()
		logger.debug("Decoding content from response and saving kid")
		data = json.loads(response.decode('utf-8'))
		kid = data.get("kid")
		payload = build_license_json(product, customer, exp, features)
		response = jwkporter.sign_json(payload, kid)
		data = json.loads(response.decode('utf-8'))
		signed_jwt = data.get("signedJwt")
		jwkporter.verify_jwt(kid, signed_jwt)
		logger.debug("Run finished successfully")
	except Exception as e:
		logger.error(e)
		sys.exit()
		
if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))