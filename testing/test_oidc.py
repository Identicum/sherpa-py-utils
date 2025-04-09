#!/usr/bin/env python3

from sherpa.utils.basics import Logger, Properties
from sherpa.utils.clients import OIDCClient
import os
import base64
import sys

properties = Properties("default.properties", "local.properties")

if "verbose" in sys.argv:
    log_level = "TRACE"
else:
    log_level = "DEBUG"

logger = Logger(os.path.basename(__file__), log_level)

def run(logger, properties):
    logger.info("Starting.")

    try:
        logger.info("Instantiating OIDCClient Class")
        oidcclient = OIDCClient(properties.get("idp_url"), logger=logger, verify=False)
        logger.info("Testing do_ropc")
        client_credentials = "{}:{}".format(properties.get("ropc_client_id"), properties.get("ropc_client_secret"))
        output = oidcclient.do_ropc(
            client_credentials=base64.b64encode(client_credentials.encode()).decode(),
            username=properties.get("ropc_test_username"),
            password=properties.get("ropc_test_password")
        )
        logger.trace(output)
        
        logger.info("Testing get_well_known")
        output = oidcclient.get_well_known()
        logger.trace(output)
        logger.info("{} finished.".format(os.path.basename(__file__)))
    except Exception as e:
        logger.error(e)

run(logger, properties)