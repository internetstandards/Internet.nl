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
tls11only              IN  A      {{TARGET_TLS11ONLY_IP}}
tls11only              IN  AAAA   {{TARGET_TLS11ONLY_IPV6}}
tls12only              IN  A      {{TARGET_TLS12ONLY_IP}}
tls12only              IN  AAAA   {{TARGET_TLS12ONLY_IPV6}}
nossl                  IN  A      {{TARGET_NOSSL_IP}}
nossl                  IN  AAAA   {{TARGET_NOSSL_IPV6}}
