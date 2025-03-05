#!/usr/bin/env python3

import argparse
import json
import os
import sys

sys.path.insert(1, "../")

from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger
from sherpa.utils.jwkporter import JWKPorter

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
	jwkporter = JWKPorter(logger, jwkporter_base_url, idp_url)

	response = jwkporter.create(client_id, client_secret)
	logger.debug("Decoding content from response and saving kid")
	data = json.loads(response.decode('utf-8'))
	kid = data.get("kid")

	response = jwkporter.sign(client_id, client_secret, exp, features,customer, product, kid)

	data = json.loads(response.decode('utf-8'))
	signed_jwt = data.get("signedJwt")
	jwkporter.verify(client_id, client_secret, kid, signed_jwt)


	logger.debug("run finished successfully")

if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))