# sherpa-py-utils is available under the MIT License. https://github.com/Identicum/sherpa-py-utils/
# Copyright (c) 2025, Identicum - https://identicum.com/
#
# Authors:
#  Martín Zielony - mzielony@identicum.com
#

import json
import time

def build_license_json(expiration, features, customer, product):
    """Builds and returns a JSON containing License info and IAT timestamp."""
    iat = int(time.time())
    return json.dumps(
        {
            "iat": iat,
            "expiration": expiration,
            "features": features,
            "customer": customer,
            "product": product,
        }
    )
