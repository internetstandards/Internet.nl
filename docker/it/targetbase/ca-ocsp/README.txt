CONTENTS:
1. HOW TO GENERATE A PRIVATE KEY AND CERTIFICATE SIGNED BY OUR CA
2. HOW TO VERIFY THAT THE OCSP SERVER IS WORKING CORRECTLY
3. HOW TO BUILD THE CA AND OCSP SERVER
4. REFERENCES

------------------------------------------------------------------------------

1. HOW TO GENERATE A PRIVATE KEY AND CERTIFICATE SIGNED BY OUR CA

To generate and sign a new certificate, on a developer machine containing
this file as part of a Git clone of the Internet.nl repo, run the following
commands:

# Set this to the domain name of the new certificate

DOMAINNAME="..."
BASEFILENAME="..."

# Go to the right directory and make sure the OCSP dir can be found
# where the ca/validation.cnf file says it should be
cd docker/it/targetbase/ca-ocsp
CA_OCSP_DIR=$(pwd)
pushd /opt/ && ln -s $CA_OCSP_DIR && popd

# Generate a private key and certificate
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=${DOMAINNAME}" -keyout ${BASEFILENAME}.key -out ${BASEFILENAME}.crt

# Generate a certificate signing request (CSR)
openssl x509 -x509toreq -in ${BASEFILENAME}.crt -out ${BASEFILENAME}.csr -signkey ${BASEFILENAME}.key

# Sign the certificate using our CA
# This will:
#    - sign the .crt file
#    - record the mapping from cert to serial number in ca/index.txt
#    - create ca/index.text.attr and ca/index.text.old
#    - bump the serial number in ca/serial
#    - put a copy of the certificate in ca/newcerts/<serial number>.pem
openssl ca -batch -startdate 150813080000Z -enddate 250813090000Z -keyfile ca/rootCA.key -cert ca/rootCA.crt -policy policy_anything -config ca/validation.cnf -notext -out ${BASEFILENAME}.crt -infiles ${BASEFILENAME}.csr

# Now you should:
# - Delete the no-longer-needed CSR file
# - Add the updated/created files to Git and commit.
# - Rebuild and re-run the targetbase and ca-oscp Docker containers (docker up --build will take care of this)
# - Install the new certificate on your webserver and tell it to staple certificates.

------------------------------------------------------------------------------

2. HOW TO VERIFY THAT THE OCSP SERVER IS WORKING CORRECTLY

$ docker-compose exec targettls1213 /bin/bash
$ cd /opt/ca-ocsp/
$ openssl ocsp -CAfile ca/rootCA.crt -issuer ca/rootCA.crt -cert /etc/ssl/certs/wildcard.test.nlnetlabs.nl.crt -url http://ca-ocsp.test.nlnetlabs.nl:8080 -resp_text -noverify
...
/etc/ssl/certs/wildcard.test.nlnetlabs.nl.crt: good

------------------------------------------------------------------------------

3. HOW TO BUILD THE CA AND OCSP SERVER

You shouldn't need to do this as it has already been done and the results committed to Git.
However, if needed and the original instructions are no longer available, here is a copy of
the original article

*********************************************************************************************
NOTE: the article uses 1024 bit length keys, but Internet.nl complains that this is too short
      so I used 4096 instead. I made this and other corrections to the article text below.
*********************************************************************************************

Taken from: https://medium.com/@bhashineen/create-your-own-ocsp-server-ffb212df8e63

Create your own OCSP server
Bhashinee Nirmali
Sep 12, 2018

This is to give an idea of how to set up OpenSSL to use OCSP. We will look into how to generate certificates, get their OCSP response from the created OCSP server and also we’ll see how to revoke certificates.

Nowadays a lot of servers and clients provide support for newer SSL/TLS features like OCSP and OCSP stapling. So for us to use those features it is necessary to have certificates issued by a well known CA or we need to have our own OCSP servers to provide the status (revoked or good) of a certificate.

This requires the support of OpenSSL in your machine. So please install OpenSSL if it is not already installed.
An OpenSSL CA requires few files and some supporting directories to work. Follow the below commands to create that folder structure(Create the directory structure according to your openssl.cnf).
mkdir -p demoCA/newcerts
touch demoCA/index.txt
echo ‘01’ > demoCA/serial

3. Copy the content of the openssl.cnf into a separate file. We will be using this new file as the configuration file to create certificates, certificate signing requests and etc. Here I have renamed it as validation.cnf. Add the following line under the section [ usr_cert ].

[ usr_cert ]
authorityInfoAccess = OCSP;URI:http://127.0.0.1:8080

4. Create a new stanza in validation.cnf as follows,

[ v3_OCSP ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = OCSPSigning

For this example, the OCSP server will be running on 127.0.0.1 on port 8080 as given in authorityInfoAccess extension.

5. Create a private key for root CA.

openssl genrsa -out rootCA.key 4096

6. Based on this key, generate a CA certificate which is valid for 10 years based on the root CA’ s private key.

openssl req -new -x509 -days 3650 -key rootCA.key -out rootCA.crt -config validation.cnf

7. Create another private key to be used as the end user private key.

openssl genrsa -out certKey.key 4096

8. Create an end user certificate based on the generated private key.

openssl req -new -x509 -days 3650 -key certKey.key -out certificate.crt -config validation.cnf

9. Generate the certificate signing request(CSR) for the generated end-user certificate.

openssl x509 -x509toreq -in certificate.crt -out CSR.csr -signkey certKey.key

10. Sign the client certificate, using above created CA and include CRL URLs and OCSP URLs in the certificate

openssl ca -batch -startdate 150813080000Z -enddate 250813090000Z -keyfile rootCA.key -cert rootCA.crt -policy policy_anything -config validation.cnf -notext -out certificate.crt -infiles CSR.csr

Creating the OCSP server

In order to host an OCSP server, an OCSP signing certificate has to be generated. Run following 2 commands.

openssl req -new -nodes -out ocspSigning.csr -keyout ocspSigning.key -config validation.cnf -extensions v3_OCSP
openssl ca -keyfile rootCA.key -cert rootCA.crt -in ocspSigning.csr -out ocspSigning.crt -config validation.cnf -extensions v3_OCSP

2. Start OCSP Server. Switch to a new terminal and run,

openssl ocsp -index demoCA/index.txt -port 8080 -rsigner ocspSigning.crt -rkey ocspSigning.key -CA rootCA.crt -text -out log.txt &

3. Verify Certificate Revocation. Switch to a new terminal and run

openssl ocsp -CAfile rootCA.crt -issuer rootCA.crt -cert certificate.crt -url http://127.0.0.1:8080 -resp_text -noverify

This will show that the certificate status is good.

Revoke a certificate

If you want to revoke the certificate run following command
openssl ca -keyfile rootCA.key -cert rootCA.crt -revoke certificate.crt

Then restart the OCSP server.
openssl ocsp -index demoCA/index.txt -port 8080 -rsigner ocspSigning.crt -rkey ocspSigning.key -CA rootCA.crt -text -out log.txt &

Verify Certificate Revocation. Switch to a new terminal and run
openssl ocsp -CAfile rootCA.crt -issuer rootCA.crt -cert certificate.crt -url http://127.0.0.1:8080 -resp_text -noverify

This will show that the certificate status as revoked.

END

4. REFERENCES

- https://medium.com/@bhashineen/create-your-own-ocsp-server-ffb212df8e63
- https://gist.github.com/soarez/9688998