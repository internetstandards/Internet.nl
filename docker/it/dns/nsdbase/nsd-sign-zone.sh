#!/bin/bash
# A helper script for signing zones.
#
# Example usage: /opt/nsd-sign-zone.sh <zone domain> <zone file name> <parent zone name> <parent zone file name> <parent zone docker container>
#
# Assumes that your unsigned zone has been added to NSD, either through an explicit zone configuration
# block, or via nsd-control addzone.
#
# See: https://www.cloudflare.com/dns/dnssec/how-dnssec-works/
#
# TODO: Use OpenDNSSec instead of ldns-xxx ?

set -e -u

if [[ $# -ne 2 && $# -ne 5 ]]; then
    echo >&2 "Usage: $0 <ZONE DOMAIN> <ZONE_FILE> (does not publish the DS to the parent zone)"
    echo >&2 "Usage: $0 <ZONE_DOMAIN> <ZONE_FILE> <PARENT ZONE DOMAIN> <PARENT ZONE FILE> <PARENT ZONE DOCKER CONTAINER NAME>"
    echo >&2 "The zone should already be added to NSD."
    exit 1
fi

ZONE_DOMAIN="$1"
ZONE_FILE="$2"
if [ $# -eq 5 ]; then
    PARENT_DOMAIN="$3"
    PARENT_FILE="$4"
    PARENT_CONTAINER="$5"
fi

cd /tmp
rm -f *sk.*

# ldns-keygen -h says:
#   The following files will be created:
#     K<name>+<alg>+<id>.key	  Public key in RR format
#     K<name>+<alg>+<id>.private  Private key in key format
#     K<name>+<alg>+<id>.ds	      DS in RR format (only for DNSSEC KSK keys)

echo "Generating KSK files for ${ZONE_DOMAIN}.."
ldns-keygen -r /dev/urandom -a RSASHA1-NSEC3-SHA1 -b 1024 ${ZONE_DOMAIN} && rename 's/K.+\./ksk./' K*

echo "Generating ZSK files for ${ZONE_DOMAIN}.."
ldns-keygen -r /dev/urandom -k -a RSASHA1-NSEC3-SHA1 -b 2048 ${ZONE_DOMAIN} && rename 's/K.+\./zsk./' K*

echo "Canonicalize all RRs in the zone, sort the zone and bump the serial number.."
ldns-read-zone -S unixtime /etc/nsd/${ZONE_FILE} > /etc/nsd/${ZONE_FILE}.bumped

echo "Signing zone file ${ZONE_FILE}.."
# group RRs with the same type into RRsets
# create RRSIGs for each RRset using the private ZSK created above
# store the public ZSK in a DNSKEY record
# if we trust the DNSKEY we can trust the zone, but can we trust the DNSKEY?
# sign the DNSKEY with the private KSK created above
# store the public KSK in another DNSKEY record
# resolves use the public KSK (DNSKEY) to validate the public ZSK (DNSKEY)
ldns-signzone -p -s $(head -n 1000 /dev/urandom | sha1sum | cut -b 1-16) -f /etc/nsd/${ZONE_FILE} /etc/nsd/${ZONE_FILE}.bumped zsk ksk
rm /etc/nsd/${ZONE_FILE}.bumped

echo "Verifying zone file ${ZONE_FILE}.."
ldns-verify-zone -k /tmp/zsk.key /etc/nsd/${ZONE_FILE}
nsd-checkzone ${ZONE_DOMAIN} /etc/nsd/${ZONE_FILE}

echo "Reloading NSD.."
nsd-control reload

if [ $# -eq 5 ]; then
    # we've now established trust in our zone
    # we have NOT connected the trust with the parent zone, for that we need to use the DS created above
    # we need to publish the DS in the parent zone
    # NOTE: the simple approach taken below is not safe if two children concurrently update the parent.
    echo "Installing delegated zone DS RR into the parent zone '${PARENT_DOMAIN}' (${PARENT_FILE}) @ ${PARENT_CONTAINER}.."
    docker cp /tmp/zsk.ds ${PARENT_CONTAINER}:/etc/nsd/tmp.ds
    docker exec ${PARENT_CONTAINER} sh -c "cat /etc/nsd/tmp.ds >> /etc/nsd/${PARENT_FILE}"
    docker exec ${PARENT_CONTAINER} rm /etc/nsd/tmp.ds
    docker exec ${PARENT_CONTAINER} nsd-checkzone ${PARENT_DOMAIN} /etc/nsd/${PARENT_FILE}
    docker exec ${PARENT_CONTAINER} /opt/nsd-sign-zone.sh ${PARENT_DOMAIN} ${PARENT_FILE}
fi