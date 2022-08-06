#!/usr/bin/bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -sha256 -days 4000 -config <(echo -e "[req]\ndistinguished_name=req") -addext keyUsage=critical,keyCertSign,cRLSign -addext basicConstraints=critical,CA:TRUE -set_serial 0 -addext subjectKeyIdentifier=hash -addext authorityKeyIdentifier=keyid:always,issuer:always -subj '/O=Pet Hub Local Organisation/OU=Pet Hub Local Org Unit/CN=Pet Hub Local CN'

chmod 666 ca.key ca.pem
