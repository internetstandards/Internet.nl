$ORIGIN test.nlnetlabs.nl.
$TTL 60
@                      IN	 SOA    ns2a.nl. admin.nlnetlabs.nl. (
                           1      ; serial
                           5S     ; refresh (5 seconds)
                           1S     ; retry (1 seconds)
                           15S    ; expire (15 seconds)
                           5S     ; minimum (5 seconds)
                       )
@                      IN  NS     ns2a.nl.
@                      IN  NS     ns2b.nl.
ca-ocsp                IN  A      {{TARGET_CA_OCSP_IP}}
ca-ocsp                IN  AAAA   {{TARGET_CA_OCSP_IPV6}}
tls1213                IN  A      {{TARGET_TLS1213_IP}}
tls1213                IN  AAAA   {{TARGET_TLS1213_IPV6}}
tls1213ipv4only        IN  A      {{TARGET_TLS1213_IP}}
tls1213sni             IN  A      {{TARGET_TLS1213_IP}}
tls1213sni             IN  AAAA   {{TARGET_TLS1213_IPV6}}
tls1213nohsts          IN  A      {{TARGET_TLS1213_IP}}
tls1213nohsts          IN  AAAA   {{TARGET_TLS1213_IPV6}}
tls1213shorthsts       IN  A      {{TARGET_TLS1213_IP}}
tls1213shorthsts       IN  AAAA   {{TARGET_TLS1213_IPV6}}
tls1213wrongcertname   IN  A      {{TARGET_TLS1213_IP}}
tls1213wrongcertname   IN  AAAA   {{TARGET_TLS1213_IPV6}}
tls1213defaultvhost    IN  A      {{TARGET_TLS1213_IP}}
tls1213defaultvhost    IN  AAAA   {{TARGET_TLS1213_IPV6}}
tls1213noocspstaple    IN  A      {{TARGET_TLS1213_IP}}
tls1213noocspstaple    IN  AAAA   {{TARGET_TLS1213_IPV6}}
tls10only              IN  A      {{TARGET_TLS10ONLY_IP}}
tls10only              IN  AAAA   {{TARGET_TLS10ONLY_IPV6}}
tls11only              IN  A      {{TARGET_TLS11ONLY_IP}}
tls11only              IN  AAAA   {{TARGET_TLS11ONLY_IPV6}}
tls12only              IN  A      {{TARGET_TLS12ONLY_IP}}
tls12only              IN  AAAA   {{TARGET_TLS12ONLY_IPV6}}
tls12onlyffdhe2048     IN  A      {{TARGET_TLS12ONLY_IP}}
tls12onlyffdhe2048     IN  AAAA   {{TARGET_TLS12ONLY_IPV6}}
tls12onlyffdhe3072     IN  A      {{TARGET_TLS12ONLY_IP}}
tls12onlyffdhe3072     IN  AAAA   {{TARGET_TLS12ONLY_IPV6}}
tls13only              IN  A      {{TARGET_TLS13ONLY_IP}}
tls13only              IN  AAAA   {{TARGET_TLS13ONLY_IPV6}}
tls130rtt              IN  A      {{TARGET_TLS130RTT_IP}}
tls130rtt              IN  AAAA   {{TARGET_TLS130RTT_IPV6}}
ssl2only               IN  A      {{TARGET_SSL2ONLY_IP}}
ssl2only               IN  AAAA   {{TARGET_SSL2ONLY_IPV6}}
ssl3only               IN  A      {{TARGET_SSL3ONLY_IP}}
ssl3only               IN  AAAA   {{TARGET_SSL3ONLY_IPV6}}
nossl                  IN  A      {{TARGET_NOSSL_IP}}
nossl                  IN  AAAA   {{TARGET_NOSSL_IPV6}}

; TLSA records generated using https://www.huque.com/bin/gen_tlsa
_443._tcp.tls1213             IN  TLSA   3 1 1 298c4f48edf1215157792a1433dbe31fa83f269bc63dccba2a83ed03aed9f705
_443._tcp.tls1213ipv4only     IN  TLSA   3 1 1 298c4f48edf1215157792a1433dbe31fa83f269bc63dccba2a83ed03aed9f705
_443._tcp.tls1213sni          IN  TLSA   3 1 1 f2bcbc0e3af0628ad6f94b16d369c8bf741437977cc105c891e69edad0e21478
_443._tcp.tls1213nohsts       IN  TLSA   3 1 1 298c4f48edf1215157792a1433dbe31fa83f269bc63dccba2a83ed03aed9f705
_443._tcp.tls1213shorthsts    IN  TLSA   3 1 1 298c4f48edf1215157792a1433dbe31fa83f269bc63dccba2a83ed03aed9f705
_443._tcp.tls1213noocspstaple IN  TLSA   3 1 1 298c4f48edf1215157792a1433dbe31fa83f269bc63dccba2a83ed03aed9f705
_443._tcp.tls10only           IN  TLSA   3 1 1 298c4f48edf1215157792a1433dbe31fa83f269bc63dccba2a83ed03aed9f705
_443._tcp.tls11only           IN  TLSA   3 1 1 298c4f48edf1215157792a1433dbe31fa83f269bc63dccba2a83ed03aed9f705
_443._tcp.tls12only           IN  TLSA   3 1 1 298c4f48edf1215157792a1433dbe31fa83f269bc63dccba2a83ed03aed9f705
_443._tcp.tls12onlyffdhe3072  IN  TLSA   3 1 1 298c4f48edf1215157792a1433dbe31fa83f269bc63dccba2a83ed03aed9f705
_443._tcp.tls12onlyffdhe2048  IN  TLSA   3 1 1 298c4f48edf1215157792a1433dbe31fa83f269bc63dccba2a83ed03aed9f705
_443._tcp.tls13only           IN  TLSA   3 1 1 298c4f48edf1215157792a1433dbe31fa83f269bc63dccba2a83ed03aed9f705
_443._tcp.tls130rtt           IN  TLSA   3 1 1 298c4f48edf1215157792a1433dbe31fa83f269bc63dccba2a83ed03aed9f705
_443._tcp.ssl2only            IN  TLSA   3 1 1 298c4f48edf1215157792a1433dbe31fa83f269bc63dccba2a83ed03aed9f705
_443._tcp.ssl3only            IN  TLSA   3 1 1 298c4f48edf1215157792a1433dbe31fa83f269bc63dccba2a83ed03aed9f705
_443._tcp.nossl               IN  TLSA   3 1 1 298c4f48edf1215157792a1433dbe31fa83f269bc63dccba2a83ed03aed9f705
