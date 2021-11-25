SHELL=/bin/bash

PY?=python
TAR?=0

BINDIR=bin
POFILESEXEC=$(BINDIR)/pofiles.py
FRONTENDEXEC=$(BINDIR)/frontend.py

REMOTEDATADIR=remote_data
MACSDIR=$(REMOTEDATADIR)/macs
CERTSSDIR=$(REMOTEDATADIR)/certs
DNSDIR=$(REMOTEDATADIR)/dns

# https://stackoverflow.com/questions/18136918/how-to-get-current-relative-directory-of-your-makefile
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(notdir $(patsubst %/,%,$(dir $(mkfile_path))))
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

ifeq ($(TAR), 0)
	POFILES_TAR_ARGS=to_tar
else
	POFILES_TAR_ARGS=from_tar
	POFILES_TAR_ARGS+=$(TAR)
endif

bin = .venv/bin
env = env PATH="${bin}:$$PATH"

.PHONY: translations translations_tar frontend update_padded_macs update_cert_fingerprints update_root_key_file

help:
	@echo 'Makefile for internet.nl'
	@echo ''
	@echo 'Usage:'
	@echo '   make translations                          combine the translation files to Django PO files'
	@echo '   make translations_tar                      create a tar from the translations'
	@echo '   make translations_tar TAR=<tar.gz file>    read the tar and update the translations'
	@echo '   make frontend                              (re)generate CSS and Javascript'
	@echo '   make update_padded_macs                    update padded MAC information'
	@echo '   make update_cert_fingerprints              update certificate fingerpint information'
	@echo '   make update_root_key_file                  update DNS root key file'

translations:
	. .venv/bin/activate && ${env} python3 $(POFILESEXEC) to_django
	@echo "Make sure to run 'compilemessages' on the server to update the actual content"

translations_tar:
	. .venv/bin/activate && ${env} python3 $(POFILESEXEC) $(POFILES_TAR_ARGS)

frontend:
	. .venv/bin/activate && ${env} python3 $(FRONTENDEXEC) js
	. .venv/bin/activate && ${env} python3 $(FRONTENDEXEC) css

update_padded_macs:
	cd $(MACSDIR); ./update-macs.sh

update_cert_fingerprints:
	cd $(CERTSSDIR); ./update-certs.sh

update_root_key_file:
	unbound-anchor -a $(DNSDIR)/root.key

venv: .venv/make_venv_complete ## Create virtual environment
.venv/make_venv_complete:
	${MAKE} clean
	python3 -m venv .venv
	. .venv/bin/activate && ${env} pip install -U pip pip-tools
	. .venv/bin/activate && ${env} pip install -Ur requirements.txt
	# . .venv/bin/activate && ${env} pip install -Ur requirements-dev.txt
	touch .venv/make_venv_complete
	${MAKE} unbound
	${MAKE} pythonwhois

clean: ## Cleanup
clean: clean_venv

clean_venv:  # Remove venv
	@echo "Cleaning venv"
	@rm -rf .venv
	@rm -f .unbound
	@rm -f .python-whois


pip-compile:  venv ## synchronizes the .venv with the state of requirements.txt
	. .venv/bin/activate && ${env} python3 -m piptools compile requirements.in

pip-upgrade: venv ## synchronizes the .venv with the state of requirements.txt
	. .venv/bin/activate && ${env} python3 -m piptools compile --upgrade requirements.in

pip-sync: venv ## synchronizes the .venv with the state of requirements.txt
	. .venv/bin/activate && ${env} python3 -m piptools sync requirements.txt

run: venv
	. .venv/bin/activate && ${env} python3 manage.py runserver 0.0.0.0:8000

run-worker: venv
	# The original worker has mapping suchas Q:w1 default etc, this translates to CELERY ROUTES in settings.py it seems.
	# Todo: currently it seems that all tasks are put on the default or celery queue as mapping is not applied.
	# Todo: Eventlet results in a database deadlock, gevent does not.
	. .venv/bin/activate && ${env} python3 -m celery -A internetnl worker -E -ldebug -Q db_worker,slow_db_worker,batch_callback,batch_main,worker_slow,celery,default,batch_slow,batch_scheduler --time-limit=300

run-worker-batch-main: venv
	. .venv/bin/activate && ${env} python3 -m celery -A internetnl worker -E -ldebug -Q batch_main --time-limit=300

run-worker-batch-scheduler: venv
	. .venv/bin/activate && ${env} python3 -m celery -A internetnl worker -E -ldebug -Q batch_scheduler --time-limit=300

run-worker-batch-callback: venv
	. .venv/bin/activate && ${env} python3 -m celery -A internetnl worker -E -ldebug -Q batch_callback --time-limit=300

run-worker-batch-slow: venv
	. .venv/bin/activate && ${env} python3 -m celery -A internetnl worker -E -ldebug -Q batch_slow --time-limit=300

run-scheduler: venv
	. .venv/bin/activate && ${env} python3 -m celery -A internetnl beat

%:
    @:

args = `arg="$(filter-out $@,$(MAKECMDGOALS))" && echo $${arg:-${1}}`

# usage: make manage <command in manage.py>
manage: venv
	# https://stackoverflow.com/questions/6273608/how-to-pass-argument-to-makefile-from-command-line
	. .venv/bin/activate && ${env} python3 manage.py $(call args,defaultstring)


unbound: venv .unbound
.unbound:
	# todo: also be able to use PYTHON_VERION from the environment
	# todo: this assumes that there is a parallels user and the code is at the /home/parallels/Internet.nl -> todo: make dynamic
	rm -rf unbound
	git clone https://github.com/internetstandards/unbound
	cd unbound && ./configure --prefix=/home/$(USER)/usr/local --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis PYTHON_VERSION=3.8 PYTHON_SITE_PKG=$(ROOT_DIR)/.venv/lib/python3.8/site-packages &&  make install
	touch .unbound

pythonwhois: venv .python-whois
.python-whois:
	rm -rf python-whois
	git clone https://github.com/internetstandards/python-whois.git
	cd python-whois && git checkout internetnl
	. .venv/bin/activate && cd python-whois && ${env} python3 setup.py install
	touch .python-whois


nassl: venv .nassl
.nassl:
	rm -rf nassl_freebsd
	git clone https://github.com/internetstandards/nassl.git nassl_freebsd
	cd nassl_freebsd && git checkout internetnl
	cd nassl_freebsd && mkdir -p bin/openssl-legacy/freebsd64
	cd nassl_freebsd && mkdir -p bin/openssl-modern/freebsd64
	cd nassl_freebsd && wget http://zlib.net/zlib-1.2.11.tar.gz
	cd nassl_freebsd && tar xvfz  zlib-1.2.11.tar.gz
	cd nassl_freebsd && git clone https://github.com/PeterMosmans/openssl.git openssl-1.0.2e
	cd nassl_freebsd && cd openssl-1.0.2e; git checkout 1.0.2-chacha; cd ..
	cd nassl_freebsd && git clone https://github.com/openssl/openssl.git openssl-master
	cd nassl_freebsd && cd openssl-master; git checkout OpenSSL_1_1_1c; cd ..
	. .venv/bin/activate && cd nassl_freebsd && ${env} python3 build_from_scratch.py
	. .venv/bin/activate && cd nassl_freebsd && ${env} python3 setup.py install
