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
	@$(PY) $(POFILESEXEC) to_django
	@echo "Make sure to run 'compilemessages' on the server to update the actual content"

translations_tar:
	@$(PY) $(POFILESEXEC) $(POFILES_TAR_ARGS)

frontend:
	@$(PY) $(FRONTENDEXEC) js
	@$(PY) $(FRONTENDEXEC) css

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

clean: ## Cleanup
clean: clean_venv

clean_venv:  # Remove venv
	@echo "Cleaning venv"
	@rm -rf .venv


pip-compile: ## synchronizes the .venv with the state of requirements.txt
	. .venv/bin/activate && ${env} python3 -m piptools compile requirements.in

pip-upgrade: ## synchronizes the .venv with the state of requirements.txt
	. .venv/bin/activate && ${env} python3 -m piptools compile --upgrade requirements.in

pip-sync: ## synchronizes the .venv with the state of requirements.txt
	. .venv/bin/activate && ${env} python3 -m piptools sync requirements.txt

run: venv
	. .venv/bin/activate && ${env} python3 manage.py runserver 0.0.0.0:8000

run-worker: venv
	# The original worker has mapping suchas Q:w1 default etc, this translates to CELERY ROUTES in settings.py it seems.
	# Todo: currently it seems that all tasks are put on the default or celery queue as mapping is not applied.
	. .venv/bin/activate && ${env} python3 -m celery -A internetnl worker -E -ldebug -Q db_worker,slow_db_worker,batch_callback,batch_main,celery,default --time-limit=300 -P eventlet


%:
    @:

args = `arg="$(filter-out $@,$(MAKECMDGOALS))" && echo $${arg:-${1}}`

manage: venv
	# https://stackoverflow.com/questions/6273608/how-to-pass-argument-to-makefile-from-command-line
	. .venv/bin/activate && ${env} python3 manage.py $(call args,defaultstring)


test:
	@echo $(call args,defaultstring)

unbound: venv .unbound
.unbound:
	# todo: this assumes that there is a parallels user and the code is at the /home/parallels/Internet.nl -> todo: make dynamic
	rm -rf unbound
	git clone https://github.com/internetstandards/unbound
	cd unbound && ./configure --prefix=/home/parallels/usr/local --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis PYTHON_VERSION=3.8 PYTHON_SITE_PKG=/samba/stitch/Internet.nl/.venv/lib/python3.8/site-packages &&  make install
	touch .unbound

pythonwhois: venv .python-whois
.python-whois:
	rm -rf python-whois
	git clone https://github.com/internetstandards/python-whois.git
	cd python-whois && git checkout internetnl
	. .venv/bin/activate && cd python-whois && ${env} python3 setup.py install
	touch .python-whois
