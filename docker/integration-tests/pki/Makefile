SHELL = /bin/bash

all: default/cert.pem default/chain.pem verify

verify: default/cert.pem | root/cert.pem
	openssl verify -verbose -CAfile $| $< | grep OK

default/key.pem default/cert.csr:
	# generate server private key and certificate signing request
	openssl req -new -newkey rsa:4096 -keyout default/key.pem -out default/cert.csr -nodes -config default/openssl.cnf

default/cert.pem: default/cert.csr extfile.ext | root/cert.pem
	# sign csr with root CA
	openssl x509 -passin pass:geheim123 -req -sha256 -CA root/cert.pem -CAkey root/key.pem -in $< -out $@ -days 365 -CAcreateserial -extfile extfile.ext

default/chain.pem: root/cert.pem
	cat $< > $@

root/cert.pem root/key.pem:
	mkdir -p ${@D}
	# create root CA
	openssl req -passin pass:geheim123 -passout pass:geheim123 -config root/openssl.cnf -x509 -sha256 -days 1825 -newkey rsa:4096 -keyout root/key.pem -out root/cert.pem

clean:
	rm -vf {default,root}/*.{pem,csr}