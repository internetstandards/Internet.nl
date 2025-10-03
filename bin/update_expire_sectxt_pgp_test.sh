#!/usr/bin/env sh

set -u

SECTXT_PATH_PROD=".well-known/security.txt"
SECTXT_PATH_TEST="docker/integration-tests/www/well-known/security.txt"

PGP_PUBKEY_PATH="interface/static/question@internet.nl_0x45028563.asc"

NOW_TS=$(date +%s)
SECONDS_IN_DAY=86400

SECTXT_THRESHOLD_MONTHS=9
SECTXT_THRESHOLD_DAYS=$(printf "%.0f\n" $(( SECTXT_THRESHOLD_MONTHS * 31 )) )

SECTXT_EXPIRE_DATE=$(sed -nr 's/^Expires: ([0-9-]+).*/\1/p' "$SECTXT_PATH_PROD")
SECTXT_EXPIRE_TS=$(date +%s -d"$SECTXT_EXPIRE_DATE")
SECTXT_EXPIRE_DAYS_LEFT=$(( ( SECTXT_EXPIRE_TS - NOW_TS ) / SECONDS_IN_DAY ))

if [ -n "$(sed -nrz 's/.*[^\r]\n.*/error\n/p' "$SECTXT_PATH_PROD")" ]; then
  echo "\e[41mNot all newlines in security.txt are CRLF\e[0m, see Unicode Format for Network Interchange (RFC 5198), please run \$ perl -i -pe 's/(?<!\\\r)\\\n/\\\r\\\n/g' \"$SECTXT_PATH_PROD\""
else
  echo "\e[42mVerified all newlines in security.txt are CRLF\e[0m conform Unicode Format for Network Interchange (RFC 5198)"
fi

if [ "$SECTXT_EXPIRE_DAYS_LEFT" -lt "$SECTXT_THRESHOLD_DAYS" ]; then
  echo "\e[41mPlease PGP re-sign security.txt\e[0m, expire within $SECTXT_THRESHOLD_MONTHS months on \e[1;41m${SECTXT_EXPIRE_DATE}\e[0m (\e[1;41m${SECTXT_EXPIRE_DAYS_LEFT}\e[0m days valid)\e[0m"
else
  echo "\e[42mNo security.txt re-sign needed\e[0m, expire after more than $SECTXT_THRESHOLD_MONTHS months on \e[1;42m${SECTXT_EXPIRE_DATE}\e[0m (\e[1;42m${SECTXT_EXPIRE_DAYS_LEFT}\e[0m days valid)\e[0m"
fi

if [ -n "$(diff "$SECTXT_PATH_PROD" "$SECTXT_PATH_TEST")" ]; then
  echo "\e[41mTest failure\e[0m security.txt in production ($SECTXT_PATH_PROD) is different than integration test ($SECTXT_PATH_TEST)"
else
  echo "\e[42mTest OK\e[0m security.txt in production is the same as integration test"
fi

GNUPGHOME=$(mktemp -d /tmp/.gnupgXXXXXX)
export GNUPGHOME
PGP_PUBKEY_EXPIRE_TS_LINES=$(gpg --batch --no-tty -q --with-colons --show-keys "$PGP_PUBKEY_PATH" | awk -F: '/^[ps]ub/{print$7}')
echo "$PGP_PUBKEY_EXPIRE_TS_LINES" | while read -r PGP_PUBKEY_EXPIRE_TS; do
  PGP_PUBKEY_EXPIRE_DATE=$(date -d"@$PGP_PUBKEY_EXPIRE_TS" -I)
  PGP_PUBKEY_EXPIRE_DAYS_LEFT=$(( ( PGP_PUBKEY_EXPIRE_TS - NOW_TS ) / SECONDS_IN_DAY ))
  if [ "$PGP_PUBKEY_EXPIRE_TS" -lt "$SECTXT_EXPIRE_TS" ]; then
    echo "\e[41mPlease extend the PGP expire\e[0m, PGP key expires on \e[1;41m${PGP_PUBKEY_EXPIRE_DATE}\e[0m (\e[1;41m${PGP_PUBKEY_EXPIRE_DAYS_LEFT}\e[0m days valid) before security.txt expires\e[0m"
  else
    echo "\e[42mNo PGP extend expire needed\e[0m, expires on \e[1;42m${PGP_PUBKEY_EXPIRE_DATE}\e[0m (\e[1;42m${PGP_PUBKEY_EXPIRE_DAYS_LEFT}\e[0m days valid) after security.txt expires\e[0m"
  fi
done

gpg --batch --no-tty -q --import "$PGP_PUBKEY_PATH"
gpg --batch --no-tty -q --verify "$SECTXT_PATH_PROD"
if [ $? -eq 0 ]
then
    echo "\e[42mPGP signature can be verified.\e[0m"
else
    echo "\e[41mPGP signature verification failed.\e[0m"
fi
rm -rf "$GNUPGHOME"
