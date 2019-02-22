#!/bin/sh
wget http://standards-oui.ieee.org/oui.txt
grep "base 16" oui.txt | awk '{printf ("%sFEFF %s\n", $1, substr($0, index($0, $4)))}' > padded_mac_vendors
python ./padded_json.py
rm oui.txt padded_mac_vendors
