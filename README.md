# tls-credentials

## Create

Before running the client or the server, TLS credentials have to be setup for secure communication. Run the `cred-gen` script to create TLS credentials for running ssl application. This script generates a `ca.crt`, `server.crt`, `server.key`, `client.crt`, and `client.key`.

```
# Used to set certificate subject alt names.
export SAN=IP.1:127.0.0.1

# Run the script
./cert-gen
```
To verify that the server and client certificates were signed by the CA, run the following commands:

```
openssl verify -CAfile ca.crt server.crt
openssl verify -CAfile ca.crt client.crt
```

## Cleaning up

Run the following command to destroy all the credentials files that were created by the `cert-gen` script:

```
./cert-destroy
```

## How to use

check ./example
