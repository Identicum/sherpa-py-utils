# sherpa-py-utils is available under the MIT License. https://github.com/Identicum/sherpa-py-utils/
# Copyright (c) 2025, Identicum - https://identicum.com/
#
# Authors:
#  Martín Zielony - mzielony@identicum.com
#

from datetime import datetime

import time

def build_license_json(product, customer, expiration, features):
    """
    Builds and returns a JSON containing License info and IAT timestamp.
    Args:
        product: Product Name.
        customer: Name of the customer the license's for.
        expiration: License Expiration Date (YYYYMMDD).
        features: Single String listing features separated by commas.
    """
    iat = int(time.time())
    
    try:
        exp = int(datetime.strptime(expiration, "%Y%m%d").timestamp())
    except ValueError:
        raise ValueError("Invalid expiration format. Please use YYYYMMDD.")
    
    features_array = [feature.strip() for feature in features.split(",")]
    if not features_array:
        raise ValueError("Features list cannot be empty.")
    
    return {
            "iat": iat,
            "product": product,
            "customer": customer,
            "expiration": exp,
            "features": features_array,
        }
