#!/bin/sh
# Random Common Name so different deploys don't share a fingerprint.
# Avoid the name UID -- it is a read-only built-in in bash, so anyone running
# this script via "bash make_cert.sh" would silently get a degraded CN.
RAND_ID=$(openssl rand -hex 16)
openssl ecparam -out cakey.pem -name prime256v1 -genkey
openssl req -new -x509 -days 3650 -key cakey.pem -out cacert.pem -subj /CN="$RAND_ID"
openssl ecparam -out serverkey.pem -name prime256v1 -genkey
openssl req -new -key serverkey.pem -out servercert.pem -subj /CN="$RAND_ID"
openssl x509 -req -days 3650 -in servercert.pem -CA cacert.pem -CAkey cakey.pem -set_serial 01 -out servercert.pem
# Tighten permissions on the private key files. Default umask of 022 would
# leave them world-readable, which is exactly what F-SEC-1 in the Phase 7
# audit flagged. Public certs (servercert.pem, cacert.pem) stay default.
chmod 600 cakey.pem serverkey.pem
