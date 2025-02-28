#!/bin/bash

rm -f ./.terraform*
rm -f ./terraform*

terraform init
terraform apply --auto-approve

