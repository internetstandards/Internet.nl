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

ifeq ($(shell uname -m),arm64)
env = env PATH="${bin}:$$PATH /usr/bin/arch -x86_64"
else
env = env PATH="${bin}:$$PATH"
endif

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

pysrcdirs = internetnl tests interface checks
pysrc = $(shell find ${pysrcdirs} -name \*.py)

bin = .venv/bin
env = env PATH="${bin}:$$PATH"

.PHONY: translations translations_tar frontend update_padded_macs update_cert_fingerprints update_root_key_file venv frontend clean clen_venv pip-compile pip-upgrade pip-upgrade-package pip-install run run-worker run-worker-batch-callback run-worker-batch-main run-worker-batch-scheduler run-heartbeat run-broker run-rabbit manage run-test-worker version unbound-3.10-github unbound-3.7-github nassl test check autofix

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
	# Rebuilds entire frontend, with minified styles and current translations.
	. .venv/bin/activate && ${env} python3 $(FRONTENDEXEC) js
	. .venv/bin/activate && ${env} python3 $(FRONTENDEXEC) css
	${MAKE} translations
	. .venv/bin/activate && ${env} python3 manage.py compilemessages --ignore=.venv
	. .venv/bin/activate && ${env} python3 manage.py collectstatic --no-input
	. .venv/bin/activate && ${env} python3 manage.py api_generate_doc


translate_content_to_main:
	# Note: you may need to run this a few times to get rid of the access denied errors...
	# This retrieves the content from the content repository and merges it with the .po files of this repo.
	# The procedure is detailed at: https://github.com/internetstandards/Internet.nl_content/blob/master/.README.md
	rm -rf tmp/locale_files/
	rm -f tmp/content_repo.tar.gz
	git clone git@github.com:internetstandards/Internet.nl_content/ tmp/locale_files/

	# If you need a specific branch people are working on:
	# git clone -b news-item_PLIS-meeting_on_IPv6 https://github.com/internetstandards/Internet.nl_content/ tmp/locale_files/

	# change dir to tmp to prevent the /tmp dir being mentioned in the resulting tar file.
	cd tmp && tar zcvf content_repo.tar.gz locale_files/*
	${MAKE} translations_tar TAR=tmp/content_repo.tar.gz
	${MAKE} translations
	. .venv/bin/activate && ${env} python3 manage.py compilemessages --ignore=.venv
	# Purposefully _not_ deleting things in the tmp dir so it allows inspection after execution.


update_padded_macs:
	chmod +x $(MACSDIR)/update-macs.sh
	cd $(MACSDIR); ./update-macs.sh

update_cert_fingerprints:
	chmod +x $(CERTSSDIR)/update-certs.sh
	chmod +x $(CERTSSDIR)/mk-ca-bundle.pl
	cd $(CERTSSDIR); ./update-certs.sh

update_root_key_file:
	unbound-anchor -a $(DNSDIR)/root.key

# Internetnl only supports python 3.7!
venv: .venv/make_venv_complete ## Create virtual environment
.venv/make_venv_complete:
	${MAKE} clean
	# todo: how to set python3 correctly on m1 macs??
	python3 -m venv .venv
	. .venv/bin/activate && ${env} pip install -U pip pip-tools
	. .venv/bin/activate && ${env} pip install -Ur requirements.txt
	. .venv/bin/activate && ${env} pip install -Ur requirements-dev.txt
	# After this you also need to make an unbound, see below for a list of commands and flavors.
	# Example: make unbound
	# You also need to make nassl
	# example: make nassl
	touch .venv/make_venv_complete

clean: ## Cleanup
clean: clean_venv

clean_venv:  # Remove venv
	@echo "Cleaning venv"
	@rm -rf .venv
	@rm -f .unbound


pip-compile:  ## compile an updated requirements.txt
	. .venv/bin/activate && ${env} python3 -m piptools compile requirements.in

pip-compile-dev:  ## compile an updated requirements{-dev}.txt
	. .venv/bin/activate && ${env} python3 -m piptools compile requirements.in
	. .venv/bin/activate && ${env} python3 -m piptools compile requirements-dev.in

pip-upgrade: ## upgrades all packages in requirements.txt to latest permitted version
	. .venv/bin/activate && ${env} python3 -m piptools compile --upgrade requirements.in

pip-upgrade-dev: ## upgrades all packages in requirements{-dev}.txt to latest permitted version
	. .venv/bin/activate && ${env} python3 -m piptools compile --upgrade requirements.in
	. .venv/bin/activate && ${env} python3 -m piptools compile --upgrade requirements-dev.in

pip-upgrade-package: ## Upgrades a specific package in the requirements.txt
	# example: make pip-upgrade-package package=django
	. .venv/bin/activate && ${env} python3 -m piptools compile --upgrade-package ${package}

pip-install:  ## install all packages from requirements.txt
	# We use pip install rather than pip-sync here, because we have external dependencies (#695)
	. .venv/bin/activate && ${env} python3 -m pip install -U -r requirements.txt

pip-install-dev:  ## install all packages requirements{-dev}.txt
	# We use pip install rather than pip-sync here, because we have external dependencies (#695)
	. .venv/bin/activate && ${env} python3 -m pip install -U -r requirements.txt -r requirements-dev.txt

run: venv
	. .venv/bin/activate && ${env} python3 manage.py runserver [::1]:8000

run-worker: venv
	# The original worker has mapping suchas Q:w1 default etc, this translates to CELERY ROUTES in settings.py it seems.
	# Todo: currently it seems that all tasks are put on the default or celery queue as mapping is not applied.
	# Todo: Eventlet results in a database deadlock, gevent does not.
	. .venv/bin/activate && ${env} python3 -m celery -A internetnl worker --pool eventlet -E -ldebug -Q db_worker,slow_db_worker,batch_callback,batch_main,worker_slow,celery,default,batch_slow,batch_scheduler,worker_nassl,ipv6_worker,resolv_worker,dnssec_worker,nassl_worker,rpki_worker,web_worker,mail_worker --time-limit=300 --concurrency=20 -n generic_worker

run-worker-batch-main: venv
	. .venv/bin/activate && ${env} python3 -m celery -A internetnl worker -E -ldebug -Q batch_main --time-limit=300 --concurrency=20 -n batch_main

run-worker-batch-scheduler: venv
	. .venv/bin/activate && ${env} python3 -m celery -A internetnl worker -E -ldebug -Q batch_scheduler --time-limit=300 --concurrency=2 -n batch_scheduler

run-worker-batch-callback: venv
	. .venv/bin/activate && ${env} python3 -m celery -A internetnl worker -E -ldebug -Q batch_callback --time-limit=300 --concurrency=2 -n batch_callback

run-worker-batch-slow: venv
	. .venv/bin/activate && ${env} python3 -m celery -A internetnl worker -E -ldebug -Q batch_slow --time-limit=300 --concurrency=2 -n batch_slow

run-heartbeat: venv
	. .venv/bin/activate && ${env} python3 -m celery -A internetnl beat

run-broker:
	docker run --rm --name=redis -p 6379:6379 redis

run-rabbit:
	docker run --rm --name=redis -p 6379:6379 redis


# %:
#     @:
#
# args = `arg="$(filter-out $@,$(MAKECMDGOALS))" && echo $${arg:-${1}}`

# If the first argument is "run"...
ifeq (manage,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "run"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
endif

ifeq (run-test-worker,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "run"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
endif



prog: # ...
    # ...


# usage: make manage <command in manage.py>
.PHONY: manage
manage: venv
	# https://stackoverflow.com/questions/6273608/how-to-pass-argument-to-makefile-from-command-line
	# Example: make manage api_check_ipv6 ARGS="--domain nu.nl"
	. .venv/bin/activate && ${env} python3 manage.py $(RUN_ARGS) $(ARGS)


run-test-worker: venv
	# Know that the worker will complain that the database is plainly been dropped, this is exactly what happens during
	# tests. It will keep on running, and the tests will run well.
	# DJANGO_DATABASE=testworker
	. .venv/bin/activate && ${env} python3 -m celery --app internetnl worker -E -ldebug --pool $(RUN_ARGS) --queues celery,default,db_worker,slow_db_worker,batch_callback,batch_main,worker_slow,batch_slow,batch_scheduler,nassl_worker,rpki_worker,ipv6_worker,mail_worker,web_worker,resolv_worker,dnssec_worker --time-limit=300 --concurrency=20 -n generic_worker > debug.log 2>&1

# compiling unbound for an x86_64 system:
ifeq ($(shell uname -m),arm64)
# arm64: -L/usr/local/Cellar/python@3.9/3.9.9/Frameworks/Python.framework/Versions/3.9/lib/ -L/usr/local/Cellar/python@3.9/3.9.9/Frameworks/Python.framework/Versions/3.9/lib/python3.9
PYTHON_LDFLAGS="-L -L/usr/local/Cellar/python@3.9/3.9.9/Frameworks/Python.framework/Versions/3.9/lib/python3.9"

# arm64: -I/usr/local/Cellar/python@3.9/3.9.9/Frameworks/Python.framework/Versions/3.9/include/python3.9
PYTHON_CPPFLAGS="-I/usr/local/Cellar/python@3.9/3.9.9/Frameworks/Python.framework/Versions/3.9/include/python3.9"
endif


version:
	. .venv/bin/activate && ${env} python3 --version
	. .venv/bin/activate && ${env} python3 manage.py version


unbound-3.9: venv .unbound-3.9
.unbound-3.9:
	rm -rf unbound
	git clone https://github.com/internetstandards/unbound
	cd unbound && ${env} ./configure --prefix=/home/$(USER)/usr/local --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis PYTHON_VERSION=3.9 PYTHON_SITE_PKG=$(ROOT_DIR)/.venv/lib/python3.9/site-packages &&  make install
	touch .unbound-3.9

unbound-3.8: venv .unbound-3.8
.unbound-3.8:
	rm -rf unbound
	git clone https://github.com/internetstandards/unbound
	cd unbound && ${env} ./configure --prefix=/home/$(USER)/usr/local --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis PYTHON_VERSION=3.8 PYTHON_SITE_PKG=$(ROOT_DIR)/.venv/lib/python3.8/site-packages &&  make install
	touch .unbound-3.8

unbound-3.7: venv .unbound-3.7
.unbound-3.7:
	rm -rf unbound
	git clone https://github.com/internetstandards/unbound
	cd unbound && ${env} ./configure --prefix=/opt/$(USER)/unbound2/ --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis PYTHON_VERSION=3.7 PYTHON_SITE_PKG=$(ROOT_DIR)/.venv/lib/python3.7/site-packages &&  make install
	touch .unbound-3.7


unbound-3.7-non-standard: venv .unbound-3.7-non-standard
.unbound-3.7-non-standard:
	rm -rf unbound
	git clone https://github.com/internetstandards/unbound
	cd unbound && ${env} ./configure --prefix=/opt/$(USER)/unbound2/ --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis PYTHON="/usr/local/bin/python3.7"  PYTHON_LDFLAGS="-L/usr/local/Cellar/python@3.8/3.8.12_1/Frameworks/Python.framework/Versions/3.8/lib/python3.8 -L/usr/local/Cellar/python@3.8/3.8.12_1/Frameworks/Python.framework/Versions/3.8/lib/python3.8/config-3.8-darwin -L/usr/local/Cellar/python@3.8/3.8.12_1/Frameworks/Python.framework/Versions/3.8/lib -lpython3.7" PYTHON_VERSION=3.7 PYTHON_SITE_PKG=$(ROOT_DIR)/.venv/lib/python3.7/site-packages &&  make install
	touch .unbound-3.7-non-standard

unbound-3.7-github: venv .unbound-3.7-github
.unbound-3.7-github:
	# Installs unbound on the github worker.
	# Todo: would it make sense to enable the venv before this so we always have the right python binaries?
	rm -rf unbound
	git clone https://github.com/internetstandards/unbound
	cd unbound && ${env} ./configure --prefix=$(ROOT_DIR)/_unbound/ --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis PYTHON_VERSION=3.7 PYTHON_SITE_PKG=$(ROOT_DIR)/.venv/lib/python3.7/site-packages &&  make install
	touch .unbound-3.7-github

unbound-3.10-github: venv .unbound-3.10-github
.unbound-3.10-github:
	rm -rf unbound
	git clone https://github.com/internetstandards/unbound
	cd unbound && ${env} ./configure --prefix=$(ROOT_DIR)/_unbound/ --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis PYTHON_VERSION=3.10 PYTHON_SITE_PKG=$(ROOT_DIR)/.venv/lib/python3.10/site-packages &&  make install
	touch .unbound-3.10-github

unbound-x86-3.9: .unbound-x86-3.9
.unbound-x86-3.9:
	# For m1 users:
	# arch -x86_64 /bin/bash
	# /usr/local/Homebrew/bin/brew install python@3.9
	# brew unlink python@3.9 && brew link python@3.9
	# /usr/local/Homebrew/bin/brew install libevent
	# /usr/local/Homebrew/bin/brew install hiredis

	rm -rf unbound
	git clone https://github.com/internetstandards/unbound
	pydir = "/usr/local/Cellar/python@3.9/3.9.9/Frameworks/Python.framework/Versions/3.9/"
	cd unbound && /usr/bin/arch -x86_64 ./configure --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis PYTHON="/usr/local/Cellar/python@3.9/3.9.9/bin/python3.9" PYTHON_LDFLAGS="-L$(pydir)lib/python3.9 -L$(pydir)lib/python3.9/config-3.9-darwin -L$(pydir)/lib -lpython3.9" PYTHON_CPPFLAGS="-I$(pydir)/include/python3.9" PYTHON_LIBDIR="$(pydir)/lib" PYTHON_SITE_PKG=$(ROOT_DIR)/.venv/lib/python3.9/site-packages && make install
	touch .unbound-x86-3.9

unbound-x86-3.8: .unbound-x86-3.8
.unbound-x86-3.8:
	# For m1 users:
	# arch -x86_64 /bin/bash
	# /usr/local/Homebrew/bin/brew install python@3.8
	# /usr/local/Homebrew/bin/brew unlink python@3.8 && /usr/local/Homebrew/bin/brew link --overwrite python@3.8
	# /usr/local/Homebrew/bin/brew install libevent
	# /usr/local/Homebrew/bin/brew install hiredis

	rm -rf unbound
	git clone https://github.com/internetstandards/unbound
	cd unbound && /usr/bin/arch -x86_64 ./configure --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis PYTHON="/usr/local/Cellar/python@3.8/3.8.12_1/bin/python3.8" PYTHON_SITE_PKG=$(ROOT_DIR)/.venv/lib/python3.8/site-packages PYTHON_LDFLAGS="-L/usr/local/Cellar/python@3.8/3.8.12_1/Frameworks/Python.framework/Versions/3.8/lib/python3.8 -L/usr/local/Cellar/python@3.8/3.8.12_1/Frameworks/Python.framework/Versions/3.8/lib/python3.8/config-3.8-darwin -L/usr/local/Cellar/python@3.8/3.8.12_1/Frameworks/Python.framework/Versions/3.8/lib -lpython3.8" PYTHON_CPPFLAGS="-I/usr/local/Cellar/python@3.8/3.8.12_1/Frameworks/Python.framework/Versions/3.8/include/python3.8" PYTHON_LIBDIR="/usr/local/Cellar/python@3.8/3.8.12_1/Frameworks/Python.framework/Versions/3.8/lib" && make install
	touch .unbound-x86-3.8

	# To use it, and not the one that comes with brew:
	# sudo /usr/local/sbin/unbound


nassl: venv .nassl
.nassl:
	# This makes a complete new checkout and build of nassl with the internet.nl code.
	rm -rf nassl_freebsd
	GIT_LFS_SKIP_SMUDGE=1 git clone https://github.com/internetstandards/nassl.git nassl_freebsd --branch internetnl
	#  cd nassl_freebsd && git checkout internetnl
	cd nassl_freebsd && mkdir -p bin/openssl-legacy/freebsd64
	cd nassl_freebsd && mkdir -p bin/openssl-modern/freebsd64
	cd nassl_freebsd && wget https://zlib.net/zlib-1.3.tar.gz
	cd nassl_freebsd && tar xvfz  zlib-1.3.tar.gz
	cd nassl_freebsd && git clone https://github.com/PeterMosmans/openssl.git openssl-1.0.2e
	# We generally follow 1.0.2-chacha branch, which moves little, but pinned to latest commit here for reproducibility
	cd nassl_freebsd && cd openssl-1.0.2e; git checkout 08802aaaa43a43c3bffc0d7cba8aed013bd14a55; cd ..
	cd nassl_freebsd && git clone https://github.com/openssl/openssl.git openssl-master
	cd nassl_freebsd && cd openssl-master; git checkout OpenSSL_1_1_1c; cd ..
	. .venv/bin/activate && cd nassl_freebsd && ${env} python3 build_from_scratch.py
	. .venv/bin/activate && cd nassl_freebsd && ${env} python3 setup.py install
	touch .nassl


test: .make.test	## run test suite
.make.test:
	DJANGO_SETTINGS_MODULE=internetnl.settings ${env} coverage run --include 'internetnl/*' --omit '*migrations*' \
		-m pytest --log-cli-level=10  -vvv -ra -k 'not integration_celery and not integration_scanners and not system' ${testargs}
	# generate coverage
	${env} coverage report
	# and pretty html
	${env} coverage html
	# ensure no model updates are commited without migrations
	# Todo: disabled because the app now requires celery to run. This should be added to the CI first.
	# ${env} python3 manage.py makemigrations --check



testcase: ${app}
	# run specific testcase
	# example: make testcase case=test_openstreetmaps
	DJANGO_SETTINGS_MODULE=internetnl.settings ${env} pytest -vvv --log-cli-level=10 -k ${case}


check: .make.check.py  ## code quality checks
.make.check.py: ${pysrc}
	# check code quality
	${env} pylama ${pysrcdirs} --skip "**/migrations/*"
	# check formatting
	${env} black --line-length 120 --check ${pysrcdirs}

autofix fix: .make.fix  ## automatic fix of trivial code quality issues
.make.fix: ${pysrc}
	# remove unused imports
	${env} autoflake -ri --remove-all-unused-imports ${pysrcdirs}
	# autoformat code
	# -q is used because a few files cannot be formatted with black, and will raise errors
	${env} black --line-length 120 -q ${pysrcdirs}
	# replaced by black: fix trivial pep8 style issues
	# replaced by black: ${env} autopep8 -ri ${pysrcdirs}
	# replaced by black: sort imports
	# replaced by black: ${env} isort -rc ${pysrcdirs}
	# do a check after autofixing to show remaining problems
	${MAKE} check


run-gunicorn:
	# 2022 02 03: gunicorn does not work with eventlet > 0.30.2, but that version has security issue GHSA-9p9m-jm8w-94p2
	# See: https://stackoverflow.com/questions/67409452/gunicorn-importerror-cannot-import-name-already-handled-from-eve
	# Running this older version is a no go. So running with gevent is required.
	# change debug level to debug...
	# sudo su -
	# service internetnl-gunicorn stop
	# sudo su internetnl
	# cd /opt/internetnl/Internet.nl/
	# source ~/internet.nl.env
	# source ./.venv/bin/activate
	# gunicorn --bind localhost:8000 --workers 3 --worker-class gevent internetnl.wsgi:application
	# or
	# sudo su internetnl
	# cd /opt/internetnl/Internet.nl/
	# source ~/internet.nl.env
	# source ./.venv/bin/activate
	# python3 -m celery --app internetnl worker -E -ldebug --pool prefork --queues db_worker,slow_db_worker,batch_callback,batch_main,worker_slow,batch_slow,batch_scheduler,celery,default --time-limit=300 --concurrency=5 -n generic_worker
	. .venv/bin/activate && ${env} gunicorn --bind localhost:8000 --workers 3 --worker-class gevent internetnl.wsgi:application --access-logfile gunicorn-access.log --error-logfile gunicorn-error.log

enable:
	source /opt/internetnl/internet.nl.env
	source /opt/internetnl/Internet.nl/.venv/bin/activate

.QA: qa
qa: fix check test
