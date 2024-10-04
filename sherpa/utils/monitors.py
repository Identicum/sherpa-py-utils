# sherpa-py-utils is available under the MIT License. https://github.com/Identicum/sherpa-py-utils/
# Copyright (c) 2024, Identicum - https://identicum.com/
#
# Author: Ezequiel O Sandoval - esandoval@identicum.com
#

from sherpa.utils.clients import OIDCClient
from importlib.metadata import version

import time


class OIDCMonitor:
    """
    OIDCMonitor provides functions for idp lambda monitoring
    """

    def __init__(self, logger, cloudwatch, idp_base_url, b64_client_credentials, verify=False):
        """
        Params
        :param logger =  RoundServices log.
        :param cloudwatch = AWS object to put metrics
        :param idp_base_url = for idp instance 'https://myidp.myorg.com'
        :param b64_client_credentials = 'user:pwd' in b64 format from client account
        """
        self.logger = logger
        self.logger.debug("OIDCMonitor version: " + version("sherpa-py-utils"))
        self.cloudwatch = cloudwatch
        self.oidc_client = OIDCClient(idp_base_url, logger, verify)
        self.b64_client_credentials = b64_client_credentials

    def _cw_put_metric_data(self, metric, value):
        self.cloudwatch.put_metric_data(
            MetricData=[{'MetricName': metric, 'Unit': 'None', 'Value': value}],
            Namespace='Applications'
        )

    def default_ropc(self, username, password):
        ropc_payload = {
            'grant_type': 'password',
            'username': username,
            'password': password,
            'scope': 'openid'
        }
        return self.ropc(ropc_payload)

    def ropc(self, ropc_payload):
        try:
            self.logger.info('Starting ROPC test.')
            start_time = time.monotonic()
            output = self.oidc_client.request_to_token_endpoint(self.b64_client_credentials, ropc_payload)
            response_time = (time.monotonic() - start_time) * 1000
            self.logger.info('ROPC test OK - response time: {} - result: {}', str(response_time), output)
            self._cw_put_metric_data('idp-ropc-response', response_time)
            return {
                'status': 'OK',
                'response_time': response_time
            }
        except Exception as err:
            self.logger.error("An error has ocurred: {}", err)
            return {
                'status': 'ERROR'
            }

    def clientcred(self):
        try:
            self.logger.info('Starting client_credentials test.')
            start_time = time.monotonic()
            output = self.oidc_client.request_to_token_endpoint(self.b64_client_credentials, {'grant_type': 'client_credentials'})
            response_time = (time.monotonic() - start_time) * 1000
            self.logger.info('client_cred test OK - response time: {} - result: {}', str(response_time), output)
            self._cw_put_metric_data('idp-client-credentials-response', response_time)
            return {
                'status': 'OK',
                'response_time': response_time
            }
        except Exception as err:
            self.logger.error("An error has ocurred: {}", err)
            return {
                'status': 'ERROR'
            }

    def claims_validation(self, scopes, username, password, claims, error_claim=None, jwt_name='id_token'):
        try:
            self.logger.info('Starting test_claims claims test.')
            ropc_payload = {
                'grant_type': 'password',
                'username': username,
                'password': password,
                'scope': " ".join(scopes)
            }
            start_time = time.monotonic()
            id_token = self.oidc_client.request_to_token_endpoint(self.b64_client_credentials, ropc_payload)[jwt_name]
            response_time = (time.monotonic() - start_time) * 1000
            self.logger.info("id_token value before validation is {}", id_token)
            output = self.oidc_client.validate_jwt(claims, id_token, error_claim)
            self.logger.info('jwt validation result {}', output)
            if output:
                self._cw_put_metric_data('idp-scopes-response', response_time)
                return {
                    'status': 'OK',
                    'response_time': response_time
                }
            else:
                self.logger.error("Invalid JWT")
                return {
                    'status': 'ERROR'
                }
        except Exception as err:
            self.logger.error("An error has ocurred: {}", err)
            return {
                'status': 'ERROR'
            }
