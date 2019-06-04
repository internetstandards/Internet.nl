$ORIGIN nlnetlabs.nl.
$TTL 60
@     IN     SOA    ns2a.nl. admin.nlnetlabs.nl. (
              1      ; serial
              5S     ; refresh (5 seconds)
              1S     ; retry (1 seconds)
             15S     ; expire (15 seconds)
              5S     ; minimum (5 seconds)
                    )
@     IN     NS     ns2a.nl.
@     IN     NS     ns2b.nl.
test  IN     NS     ns2a.nl.
test  IN     NS     ns2b.nl.
