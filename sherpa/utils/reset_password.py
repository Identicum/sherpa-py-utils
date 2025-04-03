#!/usr/bin/env python3

import os
from datetime import datetime
import sys
import string
import secrets
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from sherpa.keycloak.keycloak_lib import SherpaKeycloakAdmin

def reset_passwords(logger, properties, environment):
    logger.info("Starting.")
    keycloak_master_url = "{}/".format(properties.get("config.master_realm_url"))
    realm = properties.get("config.realm_name")
    keycloak_user = properties.get("config.deploy_username")

    password_path = "../../environment/" + environment + ".password"
    if not os.path.isfile(password_path):
        logger.error("Password file does not exist at {}", password_path)
        sys.exit(1)

    with open(password_path, "r") as password_file:
        keycloak_password = password_file.read().replace("\n", "")

    logger.trace("Connecting with user: {} and password: {}".format(keycloak_user, keycloak_password))
    keycloak_admin = SherpaKeycloakAdmin(
        logger=logger,
        local_properties=properties,
        server_url=keycloak_master_url,
        username=keycloak_user,
        password=keycloak_password,
        user_realm_name="master",
        realm_name=realm,
        verify="../../keystore/cas_cti_movil.crt",
    )       

    with open("{}.csv".format(realm), "r") as users_csv:
        user_lines = users_csv.readlines()
    log_file_name = "{}_resetpassword_{}.log".format(realm, datetime.now().replace(microsecond=0))
    users_log = open(log_file_name, "w")
    for user_line in user_lines:
        user_email = user_line.strip()
        if "@" not in user_email:
            logger.debug("INVALID_EMAIL: {}.".format(user_email))
            users_log.write('"{}","INVALID_EMAIL","",""\n'.format(user_email))
        else:
            keycloak_users = keycloak_admin.get_users(query={"username": user_email, "max": 1, "exact": True})
            if len(keycloak_users) == 1:
                random_password = generate_random_password()
                keycloak_user_id = keycloak_users[0]["id"]
                keycloak_user_createdtimestamp = keycloak_users[0]["createdTimestamp"]
                try:
                    keycloak_user_lastlogintime = keycloak_users[0]["attributes"]["lastLoginTime"][0]
                except KeyError:
                    keycloak_user_lastlogintime = None
                
                user_log_line = '"{}","{}","{}","{}"\n'.format(
                    user_email, 
                    keycloak_user_id, 
                    keycloak_user_createdtimestamp, 
                    keycloak_user_lastlogintime if keycloak_user_lastlogintime else ""
                )
                logger.debug("JSON del usuario: {}", keycloak_users[0])
                keycloak_admin.sherpa_logout_user_sessions(user_id=keycloak_user_id)

                logger.debug("Setting password \"{}\" for: {}.", random_password, user_email)
                keycloak_admin.set_user_password(user_id=keycloak_user_id, password=random_password, temporary=False)
                users_log.write(user_log_line)
            else:
                logger.debug("EMAIL_NOT_FOUND: {}.".format(user_email))
                users_log.write('"{}","EMAIL_NO_ENCONTRADO","",""\n'.format(user_email))
    users_log.close()

def generate_random_password():
    letters = string.ascii_letters
    random_letters = ""
    for i in range(8):
        random_letters += "".join(secrets.choice(letters))
    digits = string.digits
    random_digits = ""
    for i in range(4):
        random_digits += "".join(secrets.choice(digits))
    return random_letters + random_digits