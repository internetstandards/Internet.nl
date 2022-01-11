The folders in example_configuration are locations where to (usually) place certain config files. This assumes
debian 18.04. The folders have the following meaning:

The systemd services folder:
etc_systemd_system = /etc/systemd/system/

The internetnl user/source folder:
opt_internetnl_etc = /opt/internetnl/etc/


There are two variants of internet.nl:
- 1: the single scan website, where you enter a domain and the domain gets scanned.
- 2: the batch scan API site, where you enter a series of domains and get a json response with scan results after a while.

A server can be configured as either one or the other. The services are not meant to run both at the same time as the
software was not built to support that situation.
