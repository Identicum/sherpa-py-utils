FROM ghcr.io/identicum/alpine-python:latest

RUN apk add --update git bash curl unzip zip openldap-dev openssl && \
    python3 -m pip install git+https://github.com/Identicum/sherpa-py-utils.git@main

WORKDIR /usr/home

CMD ["tail", "-f", "/etc/alpine-release"]
