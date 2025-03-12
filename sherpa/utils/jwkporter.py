# sherpa-py-utils is available under the MIT License. https://github.com/Identicum/sherpa-py-utils/
# Copyright (c) 2025, Identicum - https://identicum.com/
#
# Authors:
#  Gustavo J Gallardo - ggallard@identicum.com
#

import base64
from datetime import datetime

import requests
import json
import time

from sherpa.utils.clients import OIDCClient

JWKS_SIGN_SCOPE = "jwksporter:sign"
JWKS_CRUD_SCOPE = "jwksporter:crud"
class JWKPorter:
	def __init__(self, logger, jwkporter_base_url, idp_url, client_id, client_secret):
		self.logger = logger
		self.oidc_client = OIDCClient(idp_url, logger, True)
		self.jwkporter_base_url = jwkporter_base_url
		self.idp_url = idp_url
		self.client_id = client_id
		self.client_secret = client_secret

	def _obtain_access_token(self, scope = None):
		credentials = f"{self.client_id}:{self.client_secret}".encode()
		b64_credentials = base64.b64encode(credentials).decode()
		try:
			token_response = self.oidc_client.do_client_credentials(b64_credentials, scope)
			access_token = self.oidc_client.extract_access_token(token_response)
		except Exception as err:
			self.logger.error("An error has occurred trying to obtain the access token from response: {}", err)
			raise err
		return access_token

	def sign_json(self, json_payload, kid):
		self.logger.debug("Running method to sign JWT against JWK with public key {}".format(kid))
		access_token = self._obtain_access_token(self.client_id, self.client_secret, JWKS_SIGN_SCOPE)
		endpoint_url = self.jwkporter_base_url + '/token/sign'
		
		headers = {
			"Authorization": "Bearer {}".format(access_token),
			"Content-Type": "application/json"
		}
		self.logger.debug("Calling url: {} with headers: {} and request_payload: {}", endpoint_url, headers, request_payload)
		response = requests.post(url=endpoint_url, headers=headers, data=request_payload)
		if response.status_code == 200:
			self.logger.debug("signed_payload: {}", response.content)
			return response.content
		else:
			self.logger.debug(response)
			raise Exception("Failed to sign payload: {} {}".format(response.status_code, response.text))

	def create_key(self):
		self.logger.debug("Creating a JWK Key in JWKPortainer instance")
		access_token = self._obtain_access_token(self.client_id, self.client_secret, JWKS_CRUD_SCOPE)
		endpoint_url = self.jwkporter_base_url + '/jwks/manage'
		headers = {
			"Authorization": "Bearer {}".format(access_token),
			"Content-Type": "application/json"
		}
		response = requests.post(url=endpoint_url, headers=headers)
		if response.status_code == 200:
			self.logger.debug("Created JWK: {}", response.content)
			return response.content
		else:
			self.logger.debug(response)
			raise Exception("Failed to create a JWK: {} {}".format(response.status_code, response.text))

	def verify_jwt(self, kid, signed_jwt):
		self.logger.debug("Verifying signed JWT {} with kid {}".format(signed_jwt, kid))
		access_token = self._obtain_access_token(self.client_id, self.client_secret)
		endpoint_url = self.jwkporter_base_url + '/token/verify'
		headers = {
			"Authorization": "Bearer {}".format(access_token),
			"Content-Type": "application/json"
		}
		payload = json.dumps({
			"kid": kid,
			"signedJwt": signed_jwt
		})
		response = requests.post(url=endpoint_url, headers=headers, data=payload)
		if response.status_code == 200:
			self.logger.debug("JWT Signed verified: {}", response.content)
			return response.content
		else:
			self.logger.debug(response)
			raise Exception("Failed to verify signed jwt: {} {}".format(response.status_code, response.text))
	
	def get_keys(self):
		self.logger.debug("Fetching Public Keys")
		access_token = self._obtain_access_token(self.client_id, self.client_secret)
		endpoint_url = self.jwkporter_base_url + '/jwks'

		headers = {
			"Authorization": "Bearer {}".format(access_token),
			"Content-Type": "application/json"
		}

		response = requests.get(url=endpoint_url, headers=headers)
		if response.status_code == 200:
			self.logger.debug("Got Public Keys: {}", response.content)
			return response.content
		else:
			self.logger.debug(response)
			raise Exception("Failed to get Public Keys: {} {}".format(response.status_code, response.text))