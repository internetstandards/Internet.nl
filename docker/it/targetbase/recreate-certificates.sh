#!/bin/bash

# This file recreates the certificates used by the Integration Testing.
# These include the CA key/certificates, the OCSP certificate and the
# certificates found in ./certs.
#
# Run this when one of those certificates expires.
#
# CAUTION: Make sure that you have a clean git state in relation to certificate
# and dns zone files before running this as it relies on the old information to
# be correct i.e., when replacing the TLSA records.

CA_DIR=ca-ocsp/ca
OCSP_DIR=ca-ocsp/ocsp
CERTS_DIR=certs

TLSA_ZONEFILE=../dns/submaster/nsd/test.nlnetlabs.tk

CAOCSP_CN=ca-ocsp.test.nlnetlabs.tk

BASE_DOMAIN=test.nlnetlabs.tk

CERTIFICATES="tls1213sni "
CERTIFICATES_EC=""

WILDCARD_CERTIFICATES="wildcard "
WILDCARD_CERTIFICATES_EC="wildcard "

get_tlsa_hash() {
    fname=$1.crt
    key_type=$2
    echo `openssl x509 -noout -pubkey -in ${fname} | openssl ${key_type} -pubin -outform DER 2>/dev/null |sha256sum |cut -d' ' -f1`
}

update_tlsa_hash() {
    old=$1
    new=$2
    sed -i "s/${old}/${new}/" ${TLSA_ZONEFILE}

}

create_certificate() {
    dname=$1
    fname=$2
    key_type=$3
    echo "> Getting previous TLSA hash"
    previous_tlsa_hash=`get_tlsa_hash ${fname} ${key_type}`
    echo "> Creating certificate for ${dname}"
    if test $key_type == "ec"; then
        openssl ecparam -name secp384r1 -genkey -out ${fname}.key
        openssl req -new -x509 \
            -key ${fname}.key \
            -days 1825 \
            -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=${dname}" \
            -out ${fname}.crt
    else
        openssl req -new -nodes -x509 \
            -newkey rsa:4096 \
            -days 1825 \
            -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=${dname}" \
            -keyout ${fname}.key \
            -out ${fname}.crt
    fi
    openssl x509 -x509toreq \
        -in ${fname}.crt \
        -out ${fname}.csr \
        -signkey ${fname}.key
    openssl ca -batch -notext \
        -days 1825 \
        -keyfile ${CA_DIR}/rootCA.key \
        -cert ${CA_DIR}/rootCA.crt \
        -policy policy_anything \
        -config ${CA_DIR}/validation.cnf \
        -out ${fname}.crt \
        -infiles ${fname}.csr
    rm ${fname}.csr
    echo "> Updating ${TLSA_ZONEFILE} with new TLSA hash"
    new_tlsa_hash=`get_tlsa_hash ${fname} ${key_type}`
    update_tlsa_hash ${previous_tlsa_hash} ${new_tlsa_hash}
}

# Clean
echo "::"
echo ":: Cleaning previous configuration"
echo "::"
rm -rf ${CA_DIR}/newcerts/* ${CA_DIR}/index* ${CA_DIR}/serial*
#rm -rf ${OCSP_DIR}/*
#rm -rf ${CERTS_DIR}/*.crt ${CERTS_DIR}/*.key

# Create CA
echo "::"
echo ":: Creating CA"
echo "::"
touch ${CA_DIR}/index.txt
echo 01 > ${CA_DIR}/serial
openssl genrsa -out ${CA_DIR}/rootCA.key 4096
openssl req -new -x509 \
    -days 3650 \
    -key ${CA_DIR}/rootCA.key \
    -out ${CA_DIR}/rootCA.crt \
    -config ${CA_DIR}/validation.cnf \
    -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/OU=Internet.nl/CN=${CAOCSP_CN}"

# Create OCSP
echo "::"
echo ":: Creating OCSP"
echo "::"
openssl req -new -nodes \
    -days 1825 \
    -out ${OCSP_DIR}/ocspSigning.csr \
    -keyout ${OCSP_DIR}/ocspSigning.key \
    -config ${CA_DIR}/validation.cnf \
    -extensions v3_OCSP \
    -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/OU=Internet.nl/CN=${CAOCSP_CN}"
openssl ca -batch \
    -days 1825 \
    -keyfile ${CA_DIR}/rootCA.key \
    -cert ${CA_DIR}/rootCA.crt \
    -in ${OCSP_DIR}/ocspSigning.csr \
    -out ${OCSP_DIR}/ocspSigning.crt \
    -config ${CA_DIR}/validation.cnf \
    -extensions v3_OCSP
rm ${OCSP_DIR}/ocspSigning.csr

# Create certificates
echo "::"
echo ":: Creating certificates"
echo "::"
for cert in ${CERTIFICATES}; do
    DOMAINNAME=${cert}.${BASE_DOMAIN}
    BASEFILENAME=${CERTS_DIR}/${DOMAINNAME}
    create_certificate ${DOMAINNAME} ${BASEFILENAME} "rsa"
done

echo "::"
echo ":: Creating certificates (EC)"
echo "::"
for cert in ${CERTIFICATES_EC}; do
    DOMAINNAME=${cert}.ec.${BASE_DOMAIN}
    BASEFILENAME=${CERTS_DIR}/${DOMAINNAME}
    create_certificate ${DOMAINNAME} ${BASEFILENAME} "ec"
done

echo "::"
echo ":: Creating wildcard certificates"
echo "::"
for cert in ${WILDCARD_CERTIFICATES}; do
    DOMAINNAME=*.${BASE_DOMAIN}
    BASEFILENAME=${CERTS_DIR}/${cert}.${BASE_DOMAIN}
    create_certificate ${DOMAINNAME} ${BASEFILENAME} "rsa"
done

echo "::"
echo ":: Creating wildcard certificates (EC)"
echo "::"
for cert in ${WILDCARD_CERTIFICATES_EC}; do
    DOMAINNAME=*.ec.${BASE_DOMAIN}
    BASEFILENAME=${CERTS_DIR}/${cert}.ec.${BASE_DOMAIN}
    create_certificate ${DOMAINNAME} ${BASEFILENAME} "ec"
done
