# sherpa-py-utils is available under the MIT License. https://github.com/Identicum/sherpa-py-utils/
# Copyright (c) 2024, Identicum - https://identicum.com/
#
# Author: Ezequiel O Sandoval - esandoval@identicum.com
#

import base64
import requests
import time


def validate_response(response, logger, msg, *args):
	"""
	validate a response from a requests obj, logs and raise an IOError if it is needed, also close connection.
	:param response: requests obj
	:param logger: RoundServices log - if None, will not log just throw error to default output
	:param msg: in case of error, it is a template
	:param args: params from msg
	:return: raise an error
	"""
	if not response.ok:
		error_msg = msg.format(*args) if len(args) > 0 else msg
		response.close()
		if logger is not None:
			logger.error(error_msg)
		raise IOError(error_msg)


def to_base64_creds(user, password):
	"""
	create a BasicAuth (user:pwd) encoded in Base64
	:param user: to be encoded
	:param password: to be encoded
	:return: an str that represents 'user:pwd' encoded in Base64
	"""
	message_bytes = "{}:{}".format(user, password).encode('ascii')
	base64_bytes = base64.b64encode(message_bytes)
	return base64_bytes.decode('ascii')


def wait_for_endpoint(url, iterations, interval, logger, headers={}, verify=True):
	"""
	Wait for a http endpoint until is up and running
	:param headers: http headers
	:param url: http endpoint
	:param iterations: number of retries
	:param interval: waiting interval between retries
	:param logger: sherpa log obj
	:return: None
	"""
	endpoint_ready = False
	for iteration in range(iterations):
		logger.debug("Iteration #: {}", iteration)
		try:
			logger.trace("Calling URL: {} with method: GET", url)
			http_response = requests.request("GET", url, verify=verify, headers=headers)
			logger.trace("http_response: {}, type: {}", http_response, type(http_response))
			response_code = http_response.status_code
			logger.trace("response_code: {}, type: {}", response_code, type(response_code))
			if 200 <= response_code < 300:
				endpoint_ready = True
				break
		except:
			logger.debug("Exception while trying to get endpoint: {}.", url)
		logger.info("Waiting {} seconds for endpoint: {}.", interval, url)
		time.sleep(interval)
	if not endpoint_ready:
		raise Exception("Gave up trying to connect to endpoint: {}", url)
