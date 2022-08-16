# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import json

mac_vendors = {}
with open("padded_mac_vendors", 'rb') as f:
    for line in f:
        line = line.decode('utf-8', 'ignore')
        line = line[:-2]
        s = line.split(" ", 1)
        mac_vendors[s[0]] = s[1]
with open("padded_macs.json", "w") as f:
    json.dump(mac_vendors, f)
