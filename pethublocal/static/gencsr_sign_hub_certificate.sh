#!/usr/bin/bash

openssl req -new -newkey rsa:2048 -nodes -keyout hub.key -out hub.csr -sha256 -days 4000 -subj '/CN=hub.api.surehub.io'

openssl x509 -req -in hub.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out hub.pem -days 4000 -sha256 -extfile ./hub.cnf -extensions v3_req

chmod 666 hub.key hub.pem
