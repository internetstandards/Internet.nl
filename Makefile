SHELL=/bin/bash

PY?=python
TAR?=0

BINDIR=bin
FRONTENDEXEC=$(BINDIR)/frontend.py

REMOTEDATADIR=remote_data
MACSDIR=$(REMOTEDATADIR)/macs
CERTSSDIR=$(REMOTEDATADIR)/certs
DNSDIR=$(REMOTEDATADIR)/dns

# default version if nothing is provided by environment
RELEASE ?= 0.0.0-dev0

ifeq ($(shell uname -m),arm64)
_env = env PATH="${bin}:$$PATH /usr/bin/arch -x86_64"
else
_env = env PATH="${bin}:$$PATH"
endif

# https://stackoverflow.com/questions/18136918/how-to-get-current-relative-directory-of-your-makefile
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(notdir $(patsubst %/,%,$(dir $(mkfile_path))))
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

pysrcdirs = internetnl tests interface checks integration_tests docker
pysrc = $(shell find ${pysrcdirs} -name \*.py)

bin = .venv/bin
_env ?= env PATH="${bin}:$$PATH"

.PHONY: translations translations_tar frontend update_cert_fingerprints update_container_documentation update_padded_macs update_root_key_file venv frontend clean clen_venv pip-compile pip-upgrade pip-upgrade-package pip-install run run-worker run-worker-batch-callback run-worker-batch-main run-worker-batch-scheduler run-heartbeat run-broker run-rabbit manage run-test-worker version unbound-3.10-github unbound-3.7-github nassl test check autofix integration-tests batch-tests

help:
	@echo 'Makefile for internet.nl'
	@echo ''
	@echo 'Usage:'
	@echo '   make update_content                        update the translation files from content repo.'
	@echo '                                              Optional branch=x to use a specific content repo branch.'
	@echo '   make frontend                              (re)generate CSS and Javascript'
	@echo '   make update_cert_fingerprints              update certificate fingerprint information'
	@echo '   make update_container_documentation        update container table for documentation'
	@echo '   make update_padded_macs                    update padded MAC information'
	@echo '   make update_root_key_file                  update DNS root key file'

translations:
	. .venv/bin/activate && ${_env} python3 $(POFILESEXEC) to_django
	@echo "Make sure to run 'compilemessages' on the server to update the actual content"

translations_tar:
	. .venv/bin/activate && ${_env} python3 $(POFILESEXEC) $(POFILES_TAR_ARGS)

frontend:
	# Rebuilds entire frontend, with minified styles and current translations.
	. .venv/bin/activate && ${_env} python3 $(FRONTENDEXEC) js
	. .venv/bin/activate && ${_env} python3 $(FRONTENDEXEC) css
	${MAKE} translations
	. .venv/bin/activate && ${_env} python3 manage.py compilemessages --ignore=.venv
	. .venv/bin/activate && ${_env} python3 manage.py collectstatic --no-input
	. .venv/bin/activate && ${_env} python3 manage.py api_generate_doc

	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools bin/lint.sh ${pysrcdirs}

branch ?= main
update_content:
    # This retrieves the content from the content repository and merges it with the .po files of this repo.
    # The procedure is detailed at: https://github.com/internetstandards/Internet.nl_content/blob/master/.README.md
	rm -rf tmp/locale_files/
	rm -f tmp/content_repo.tar.gz
	mkdir -p tmp/locale_files/
	git clone -b $(branch) git@github.com:internetstandards/Internet.nl_content/ tmp/locale_files/
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools bin/update_translations.sh
	rm -rf tmp/locale_files

update_cert_fingerprints:
	chmod +x $(CERTSSDIR)/update-certs.sh
	chmod +x $(CERTSSDIR)/mk-ca-bundle.pl
	cd $(CERTSSDIR); ./update-certs.sh

update_container_documentation:
	chmod +x bin/update_container_documentation.sh
	./bin/update_container_documentation.sh

update_padded_macs:
	chmod +x $(MACSDIR)/update-macs.sh
	cd $(MACSDIR); ./update-macs.sh

update_root_key_file:
	unbound-anchor -a $(DNSDIR)/root.key

# Internetnl only supports python 3.7!
venv: .venv/make_venv_complete ## Create virtual environment
.venv/make_venv_complete:
	${MAKE} clean
	# todo: how to set python3 correctly on m1 macs??
	python3 -m venv .venv
	. .venv/bin/activate && ${_env} pip install -U pip pip-tools
	. .venv/bin/activate && ${_env} pip install -Ur requirements.txt
	. .venv/bin/activate && ${_env} pip install -Ur requirements-dev.txt
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
	. .venv/bin/activate && ${_env} python3 -m piptools compile requirements.in

pip-compile-dev:  ## compile an updated requirements{-dev}.txt
	. .venv/bin/activate && ${_env} python3 -m piptools compile requirements.in
	. .venv/bin/activate && ${_env} python3 -m piptools compile requirements-dev.in

pip-upgrade: ## upgrades all packages in requirements.txt to latest permitted version
	. .venv/bin/activate && ${_env} python3 -m piptools compile --upgrade requirements.in

pip-upgrade-dev: ## upgrades all packages in requirements{-dev}.txt to latest permitted version
	. .venv/bin/activate && ${_env} python3 -m piptools compile --upgrade requirements.in
	. .venv/bin/activate && ${_env} python3 -m piptools compile --upgrade requirements-dev.in

pip-upgrade-package: ## Upgrades a specific package in the requirements.txt
	# example: make pip-upgrade-package package=django
	. .venv/bin/activate && ${_env} python3 -m piptools compile --upgrade-package ${package}

pip-install:  ## install all packages from requirements.txt
	# We use pip install rather than pip-sync here, because we have external dependencies (#695)
	. .venv/bin/activate && ${_env} python3 -m pip install -U -r requirements.txt

pip-install-dev:  ## install all packages requirements{-dev}.txt
	# We use pip install rather than pip-sync here, because we have external dependencies (#695)
	. .venv/bin/activate && ${_env} python3 -m pip install -U -r requirements.txt -r requirements-dev.txt

run-app: venv
	. .venv/bin/activate && ${_env} python3 manage.py runserver [::1]:8000

run-worker: venv
	# The original worker has mapping suchas Q:w1 default etc, this translates to CELERY ROUTES in settings.py it seems.
	# Todo: currently it seems that all tasks are put on the default or celery queue as mapping is not applied.
	# Todo: Eventlet results in a database deadlock, gevent does not.
	. .venv/bin/activate && ${_env} python3 -m celery -A internetnl worker --pool eventlet -E -ldebug -Q db_worker,slow_db_worker,batch_callback,batch_main,worker_slow,celery,default,batch_slow,batch_scheduler,worker_nassl,ipv6_worker,resolv_worker,dnssec_worker,nassl_worker,rpki_worker,web_worker,mail_worker --time-limit=300 --concurrency=20 -n generic_worker

run-worker-batch-main: venv
	. .venv/bin/activate && ${_env} python3 -m celery -A internetnl worker -E -ldebug -Q batch_main --time-limit=300 --concurrency=20 -n batch_main

run-worker-batch-scheduler: venv
	. .venv/bin/activate && ${_env} python3 -m celery -A internetnl worker -E -ldebug -Q batch_scheduler --time-limit=300 --concurrency=2 -n batch_scheduler

run-worker-batch-callback: venv
	. .venv/bin/activate && ${_env} python3 -m celery -A internetnl worker -E -ldebug -Q batch_callback --time-limit=300 --concurrency=2 -n batch_callback

run-worker-batch-slow: venv
	. .venv/bin/activate && ${_env} python3 -m celery -A internetnl worker -E -ldebug -Q batch_slow --time-limit=300 --concurrency=2 -n batch_slow

run-heartbeat: venv
	. .venv/bin/activate && ${_env} python3 -m celery -A internetnl beat

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
	. .venv/bin/activate && ${_env} python3 manage.py $(RUN_ARGS) $(ARGS)

# use venv prerequisite or empty env variable depending on running in docker or old environment
ifeq (,$(wildcard /.dockerenv))
run-test-worker: venv
else
run-test-worker: _env=
run-test-worker:
endif
	# Know that the worker will complain that the database is plainly been dropped, this is exactly what happens during
	# tests. It will keep on running, and the tests will run well.
	# DJANGO_DATABASE=testworker
	${_env} python3 -m celery --app internetnl worker -E -ldebug --pool $(RUN_ARGS) --queues celery,default,db_worker,slow_db_worker,batch_callback,batch_main,worker_slow,batch_slow,batch_scheduler,nassl_worker,rpki_worker,ipv6_worker,mail_worker,web_worker,resolv_worker,dnssec_worker --time-limit=300 --concurrency=20 -n generic_worker > debug.log 2>&1

# compiling unbound for an x86_64 system:
ifeq ($(shell uname -m),arm64)
# arm64: -L/usr/local/Cellar/python@3.9/3.9.9/Frameworks/Python.framework/Versions/3.9/lib/ -L/usr/local/Cellar/python@3.9/3.9.9/Frameworks/Python.framework/Versions/3.9/lib/python3.9
PYTHON_LDFLAGS="-L -L/usr/local/Cellar/python@3.9/3.9.9/Frameworks/Python.framework/Versions/3.9/lib/python3.9"

# arm64: -I/usr/local/Cellar/python@3.9/3.9.9/Frameworks/Python.framework/Versions/3.9/include/python3.9
PYTHON_CPPFLAGS="-I/usr/local/Cellar/python@3.9/3.9.9/Frameworks/Python.framework/Versions/3.9/include/python3.9"
endif


version:
	. .venv/bin/activate && ${_env} python3 --version
	. .venv/bin/activate && ${_env} python3 manage.py version


unbound-3.9: venv .unbound-3.9
.unbound-3.9:
	rm -rf unbound
	git clone https://github.com/internetstandards/unbound
	cd unbound && ${_env} ./configure --prefix=/home/$(USER)/usr/local --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis PYTHON_VERSION=3.9 PYTHON_SITE_PKG=$(ROOT_DIR)/.venv/lib/python3.9/site-packages &&  make install
	touch .unbound-3.9

unbound-3.8: venv .unbound-3.8
.unbound-3.8:
	rm -rf unbound
	git clone https://github.com/internetstandards/unbound
	cd unbound && ${_env} ./configure --prefix=/home/$(USER)/usr/local --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis PYTHON_VERSION=3.8 PYTHON_SITE_PKG=$(ROOT_DIR)/.venv/lib/python3.8/site-packages &&  make install
	touch .unbound-3.8

unbound-3.7: venv .unbound-3.7
.unbound-3.7:
	rm -rf unbound
	git clone https://github.com/internetstandards/unbound
	cd unbound && ${_env} ./configure --prefix=/opt/$(USER)/unbound2/ --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis PYTHON_VERSION=3.7 PYTHON_SITE_PKG=$(ROOT_DIR)/.venv/lib/python3.7/site-packages &&  make install
	touch .unbound-3.7


unbound-3.7-non-standard: venv .unbound-3.7-non-standard
.unbound-3.7-non-standard:
	rm -rf unbound
	git clone https://github.com/internetstandards/unbound
	cd unbound && ${_env} ./configure --prefix=/opt/$(USER)/unbound2/ --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis PYTHON="/usr/local/bin/python3.7"  PYTHON_LDFLAGS="-L/usr/local/Cellar/python@3.8/3.8.12_1/Frameworks/Python.framework/Versions/3.8/lib/python3.8 -L/usr/local/Cellar/python@3.8/3.8.12_1/Frameworks/Python.framework/Versions/3.8/lib/python3.8/config-3.8-darwin -L/usr/local/Cellar/python@3.8/3.8.12_1/Frameworks/Python.framework/Versions/3.8/lib -lpython3.7" PYTHON_VERSION=3.7 PYTHON_SITE_PKG=$(ROOT_DIR)/.venv/lib/python3.7/site-packages &&  make install
	touch .unbound-3.7-non-standard

unbound-3.7-github: venv .unbound-3.7-github
.unbound-3.7-github:
	# Installs unbound on the github worker.
	# Todo: would it make sense to enable the venv before this so we always have the right python binaries?
	rm -rf unbound
	git clone https://github.com/internetstandards/unbound
	cd unbound && ${_env} ./configure --prefix=$(ROOT_DIR)/_unbound/ --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis PYTHON_VERSION=3.7 PYTHON_SITE_PKG=$(ROOT_DIR)/.venv/lib/python3.7/site-packages &&  make install
	touch .unbound-3.7-github

unbound-3.10-github: venv .unbound-3.10-github
.unbound-3.10-github:
	rm -rf unbound
	git clone https://github.com/internetstandards/unbound
	cd unbound && ${_env} ./configure --prefix=$(ROOT_DIR)/_unbound/ --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis PYTHON_VERSION=3.10 PYTHON_SITE_PKG=$(ROOT_DIR)/.venv/lib/python3.10/site-packages &&  make install
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
	. .venv/bin/activate && cd nassl_freebsd && ${_env} python3 build_from_scratch.py
	. .venv/bin/activate && cd nassl_freebsd && ${_env} python3 setup.py install
	touch .nassl


old-test: .make.test
.make.test:
	DJANGO_SETTINGS_MODULE=internetnl.settings ${_env} coverage run --omit '*migrations*'\
		-m pytest --log-cli-level=10  -vvv -ra -k 'not integration_celery and not integration_scanners and not system' \
		--ignore=integration_tests/ ${test_args}
	# generate coverage
	${_env} coverage report
	# and pretty html
	${_env} coverage html
	# ensure no model updates are commited without migrations
	# Todo: disabled because the app now requires celery to run. This should be added to the CI first.
	# ${_env} python3 manage.py makemigrations --check

testcase: ${app}
	# run specific testcase
	# example: make testcase case=test_openstreetmaps
	DJANGO_SETTINGS_MODULE=internetnl.settings ${_env} pytest -vvv --log-cli-level=10 -k ${case}


old-check: .make.check.py
.make.check.py: ${pysrc}
	# check code quality
	${_env} pylama ${pysrcdirs} --skip "**/migrations/*"
	# check formatting
	${_env} black --line-length 120 --check ${pysrcdirs}

autofix: .make.fix  ## automatic fix of trivial code quality issues
.make.fix: ${pysrc}
	# remove unused imports
	${_env} autoflake -ri --remove-all-unused-imports ${pysrcdirs}
	# autoformat code
	# -q is used because a few files cannot be formatted with black, and will raise errors
	${_env} black --line-length 120 -q ${pysrcdirs}
	# replaced by black: fix trivial pep8 style issues
	# replaced by black: ${_env} autopep8 -ri ${pysrcdirs}
	# replaced by black: sort imports
	# replaced by black: ${_env} isort -rc ${pysrcdirs}
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
	. .venv/bin/activate && ${_env} gunicorn --bind localhost:8000 --workers 3 --worker-class gevent internetnl.wsgi:application --access-logfile gunicorn-access.log --error-logfile gunicorn-error.log

enable:
	source /opt/internetnl/internet.nl.env
	source /opt/internetnl/Internet.nl/.venv/bin/activate

.QA: qa
qa: fix check test

# create some shorthands
env ?=
environment ?= ${env}
test_args ?= ${testargs}
services ?= ${service}
ifeq (${environment},dev)
	environment = develop
endif

# allow overriding settings
ifneq (,$(wildcard docker/local.env))
$(info )
$(info A `docker/local.env` exists which may override default behaviour!)
$(info )
$(info File contents:)
$(info )
$(info $(shell cat docker/local.env))
$(info )

localenv =--env-file=docker/local.env
endif

# command used to bring projects up
DOCKER_COMPOSE_UP_PULL_CMD=docker compose ${compose_args} \
	--env-file=docker/defaults.env \
	--env-file=docker/${environment}.env \
	${localenv}

# after the project is up, we can use the project name instead of providing all environment files
DOCKER_COMPOSE_CMD=docker compose ${compose_args} --project-name=internetnl-${environment}

# build.env includes all compose files, so this will build all services images
DOCKER_COMPOSE_BUILD_CMD=docker compose ${compose_args} \
	--env-file=docker/defaults.env \
	--env-file=docker/build.env

build docker-compose-build:
	${DOCKER_COMPOSE_BUILD_CMD} build ${build_args} --build-arg=RELEASE=${RELEASE} ${services}

build-no-cache docker-compose-build-no-cache: build
build-no-cache docker-compose-build-no-cache: build_args=--no-cache

docker-compose:
	${DOCKER_COMPOSE_CMD} ${args}

up docker-compose-up:
	${DOCKER_COMPOSE_UP_PULL_CMD} up --wait --no-build --remove-orphans --timeout=0 ${services}
	@if [ "${environment}" = "test" ]; then echo -e "\n🚀 Running on http://localhost:8081"; fi
	@if [ "${environment}" = "develop" ]; then echo -e "\n🚀 Running on http://localhost:8080"; fi
	@if [ "${environment}" = "batch-test" ]; then echo -e "\n🚀 Running on http://localhost:8081"; fi

up-no-wait:
	${DOCKER_COMPOSE_UP_PULL_CMD} up --detach --no-build --remove-orphans --timeout=0 ${services}

run docker-compose-run:
	${DOCKER_COMPOSE_UP_PULL_CMD} up --watch --remove-orphans --timeout=0 ${services}

restart docker-compose-restart:
	${DOCKER_COMPOSE_CMD} restart --no-deps ${services}

docker-compose-up-build-no-deps:
	${DOCKER_COMPOSE_UP_PULL_CMD} up --wait --build --no-deps --build-arg=RELEASE=${RELEASE} ${services}

up-no-deps:
	${DOCKER_COMPOSE_UP_PULL_CMD} up --wait --no-deps ${services}

ps docker-compose-ps:
	${DOCKER_COMPOSE_CMD} ps

docker-compose-app-attach:
	${DOCKER_COMPOSE_CMD} attach -ti app

logs docker-compose-logs: services=webserver app worker worker-nassl worker-slow resolver test-target
logs docker-compose-logs:
	${DOCKER_COMPOSE_CMD} logs --follow ${services}

logs-all docker-compose-logs-all:
	${DOCKER_COMPOSE_CMD} logs --follow

logs-all-dump:
	${DOCKER_COMPOSE_CMD} logs

exec docker-compose-exec: service=app
exec docker-compose-exec: cmd=/bin/bash
exec docker-compose-exec:
	${DOCKER_COMPOSE_CMD} exec --user root ${service} ${cmd}

run-shell: service=app
run-shell: cmd=/bin/bash
run-shell:
	${DOCKER_COMPOSE_UP_PULL_CMD} run ${run_args} --entrypoint ${cmd} ${service}

# show result of merging .yml docker compose config files
docker-compose-config:
	${DOCKER_COMPOSE_UP_PULL_CMD} config

# dump the merged compose config to a file with the versions of docker and compose for easier comparison
docker-compose-config-to-file:
	${DOCKER_COMPOSE_UP_PULL_CMD} config > "config-compose-$$(docker compose version --short)-$$(docker version -f 'server-{{.Server.Version}}-client-{{.Client.Version}}').yml"

docker-compose-create-superuser:
	${DOCKER_COMPOSE_CMD} exec app ./manage.py shell -c "from django.contrib.auth.models import User; User.objects.create_superuser('admin', 'admin@example.com', 'admin')"

docker-compose-rabbitmq-admin:
	open "http://guest:guest@localhost:$$(${DOCKER_COMPOSE_CMD} port rabbitmq 15672)"

postgres-shell docker-compose-postgres-shell:
	${DOCKER_COMPOSE_CMD} exec postgres psql --username "internetnl" --dbname "internetnl_db1"

redis-shell docker-compose-redis-shell:
	${DOCKER_COMPOSE_CMD} exec redis redis-cli

docker-compose-reset-test-target:
	curl http://localhost:8080/clear/target.test/ -s

# pause all containers, but don't remove them
stop docker-compose-stop:
	${DOCKER_COMPOSE_CMD} stop

# stop and remove all containers, but keep volumes (eg: routinator cache, databases)
down docker-compose-down:
	${DOCKER_COMPOSE_CMD} down --timeout=0

down-remove-volumes docker-compose-down-remove-volumes:
	${DOCKER_COMPOSE_CMD} down --volumes

docker-compose-reset:
	${DOCKER_COMPOSE_CMD} down --volumes
	docker network prune -f

pull docker-compose-pull:
	${DOCKER_COMPOSE_UP_PULL_CMD} pull ${pull_args}

test-runner-shell integration-tests-shell docker-compose-test-runner-shell: env=test
test-runner-shell integration-tests-shell docker-compose-test-runner-shell:
	${DOCKER_COMPOSE_UP_PULL_CMD} run --entrypoint /bin/bash test-runner

batch-api-create-db-indexes docker-compose-batch-api-create-db-indexes:
	${DOCKER_COMPOSE_CMD} exec app ./manage.py api_create_db_indexes

tests ?= .
integration-tests: env=test
integration-tests:
	${DOCKER_COMPOSE_UP_PULL_CMD} run --rm test-runner --browser=firefox --screenshot=only-on-failure --video=retain-on-failure --junit-xml=test-results.xml ${_test_args} ${test_args} -k'${tests}' integration_tests/common/ integration_tests/integration/
	@echo -e "\nTo run with only specific tests use the 'tests' argument with part of the test's name, for example: make integration-tests tests=test_index_http_ok\n"

integration-tests-verbose: _test_args=--verbose --verbose
integration-tests-verbose: integration-tests

integration-tests-all-browser: _test_args=--browser=firefox --browser=chromium --browser=webkit
integration-tests-all-browser: integration-tests

integration-tests-trace: _test_args=--tracing=retain-on-failure
integration-tests-trace: integration-tests

batch-tests: env=batch-test
batch-tests:
	${DOCKER_COMPOSE_UP_PULL_CMD} run --rm test-runner --browser=firefox --screenshot=only-on-failure --video=retain-on-failure --junit-xml=test-results.xml ${_test_args} ${test_args} -k'${tests}' integration_tests/common/ integration_tests/batch/

batch-tests-verbose: _test_args=--verbose --verbose
batch-tests-verbose: batch-tests

batch-tests-shell: env=batch-test
batch-tests-shell:
	${DOCKER_COMPOSE_UP_PULL_CMD} run --entrypoint /bin/bash test-runner


live-tests:
	COMPOSE_FILE=docker/compose.test-runner-live.yaml docker compose run --rm test-runner-live \
		-ra --screenshot=only-on-failure --video=retain-on-failure --junit-xml=test-results.xml ${test_args} integration_tests/live/

# use OS specific hostname for Docker host
ifeq ($(shell uname -s),Darwin)
docker_host = host.docker.internal
else
docker_host = host-gateway
endif

DOCKER_COMPOSE_DEVELOP_CMD=COMPOSE_FILE=docker/compose.test-runner-develop.yaml docker compose

# this runs limited live test suite against the development environment to test its sanity
develop-tests development-environment-tests:
	APP_URLS=http://${docker_host}:8080  ${DOCKER_COMPOSE_DEVELOP_CMD} run --rm test-runner-development-environment \
		-ra --screenshot=only-on-failure --video=retain-on-failure --junit-xml=test-results.xml ${test_args} integration_tests/develop/

develop-tests-shell:
	${DOCKER_COMPOSE_DEVELOP_CMD} run --rm --entrypoint bash test-runner-development-environment


DOCKER_COMPOSE_TEST_CMD=COMPOSE_FILE=docker/compose.yaml:docker/compose.test.yaml \
	docker compose ${compose_args} \
	--env-file=docker/defaults.env \
	--env-file=docker/test.env \
	${localenv}

test:
	${DOCKER_COMPOSE_TEST_CMD} run --rm test python3 \
	-m coverage run \
	-m pytest -vvv -ra \
	--junit-xml=test-results.xml \
	$(filter-out integration_tests,${pysrcdirs}) \
    -k'${tests}' \
	${test_args}

test-shell:
	${DOCKER_COMPOSE_TEST_CMD} run --rm test bash

test-all:
	# bring running environments down
	$(MAKE) down environment=develop
	$(MAKE) down environment=test
	$(MAKE) down environment=batch-test
	# build all images
	$(MAKE) build
	# run checks
	$(MAKE) check
	# run unittests
	$(MAKE) up environment=test
	$(MAKE) test
	$(MAKE) down environment=test
	# run development environment tests
	$(MAKE) up environment=develop
	$(MAKE) develop-tests
	$(MAKE) down environment=develop
	# run integration tests
	$(MAKE) up environment=test
	$(MAKE) integration-tests
	$(MAKE) down environment=test
	# run batch
	$(MAKE) up environment=batch-test
	$(MAKE) batch-tests
	$(MAKE) down environment=batch-test

DOCKER_COMPOSE_TOOLS_CMD=COMPOSE_FILE=docker/compose.tools.yaml docker compose

makemigrations:
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools env SKIP_SECRET_KEY_CHECK=True CACHE_LOCATION= ENABLE_BATCH= ./manage.py makemigrations

lint:
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools bin/lint.sh ${pysrcdirs}

check:
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools bin/check.sh ${pysrcdirs}

fix:
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools bin/fix.sh ${pysrcdirs}
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools bin/lint.sh ${pysrcdirs}

check-gixy: env=test
check-gixy:
	${DOCKER_COMPOSE_CMD} exec webserver /opt/gixy/bin/gixy /etc/nginx/nginx.conf

build-linttest linttest-build:
	${DOCKER_COMPOSE_TOOLS_CMD} build tools

linttest-shell:
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools bash

requirements: requirements.txt requirements-dev.txt

requirements.txt: requirements.in
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools pip-compile requirements.in

requirements-dev.txt: requirements-dev.in
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools pip-compile requirements-dev.in

integration-tests-debug:
	${_env} pytest --setup-show -v --capture=no integration-tests ${test_args}

# run integration-tests against development environment instance
integration-tests-against-develop: _env:=${_env} INTERNETNL_USE_DOCKER_COMPOSE_PROJECT="internetnl"
integration-tests-against-develop: integration-tests

# reset caches in development environment and run integration-tests against development environment instance
integration-tests-reset-and-against-develop: docker-compose-redis-clear-celery-results integration-tests-against-develop

# Docker container runtime for MacOS
# until nassl can be built for ARM: https://github.com/nabla-c0d3/nassl/issues/39
# it is required to emulate x86_64 under Apple Silicon Macs
docker-compose-runtime-start:
	colima start --cpu 4 --memory 8 --arch x86_64

docker-compose-runtime-stop:
	colima stop

images = $(patsubst %.py,%.png,$(wildcard documentation/images/*.py))
documentation-images: ${images}
documentation/images/%.png: documentation/images/%.py | ${nwdiag}
	docker run -it --rm -v "$${PWD}/$(@D)/":/$(@D) -w /$(@D) gtramontina/diagrams:0.23.1 $(<F)

test-%: env=test
test-up test-down test-build test-stop: test-%: %

batch_user ?=
batch_host ?= dev-docker.batch.internet.nl
batch_api = https://${batch_host}/api/batch/v2
TMPDIR ?= /tmp

batch_submit_web_1k batch_submit_web_5k batch_submit_web_10k batch_submit_web_15k batch_submit_web_20k: batch_submit_web_%k: ${TMPDIR}/batch_request_%k_web.json
	auth="${batch_user}:$$(keyring get internet.nl-batch ${batch_user})" ;\
	response=$$(curl -s -u $$auth ${batch_api}/requests -H "Content-type: application/json" -d @$<) ;\
	echo $$response ;\
	request_id=$$(echo $$response | jq .request.request_id) ;\
	watch "curl -s -u $$auth ${batch_api}/requests/$$request_id | jq .; curl -s -u $$auth ${batch_api}/requests/$$request_id/results | jq .request,.error" ;

${TMPDIR}/batch_request_%k_web.json: ${TMPDIR}/tranco_list_%k.txt
	# convert to json batch request file
	jq '{domains:.|split("\n")|map(select(length>0)),name:"tranco $*k - web",type:"web"}' -Rsc $< > $@

batch_submit_mail_1k batch_submit_mail_5k batch_submit_mail_10k batch_submit_mail_15k batch_submit_mail_20k: batch_submit_mail_%k: ${TMPDIR}/batch_request_%k_mail.json
	auth="${batch_user}:$$(keyring get internet.nl-batch ${batch_user})" ;\
	response=$$(curl -s -u $$auth ${batch_api}/requests -H "Content-type: application/json" -d @$<) ;\
	echo $$response ;\
	request_id=$$(echo $$response | jq .request.request_id) ;\
	watch "curl -s -u $$auth ${batch_api}/requests/$$request_id | jq .; curl -s -u $$auth ${batch_api}/requests/$$request_id/results | jq .request,.error" ;

${TMPDIR}/batch_request_%k_mail.json: ${TMPDIR}/tranco_list_%k.txt
	# convert to json batch request file
	jq '{domains:.|split("\n")|map(select(length>0)),name:"tranco $*k - mail",type:"mail"}' -Rsc $< > $@

${TMPDIR}/tranco_list_%k.txt: ${TMPDIR}/tranco_list.txt
	# get first $*k of domains
	head -n$*000 $< | tr -d \r > $@

${TMPDIR}/tranco_list.txt:
	# download tranco list, unzip, convert from csv to plain list of domains
	curl -Ls https://tranco-list.eu/download_daily/4Q39X | bsdtar -xOf - | cut -d, -f2 > $@

# convenience target, will build and run all services for development and output logs for the relevant ones
develop:
	# (re)build all services
	${MAKE} build env=develop
	# bring entire environment up
	${MAKE} up-no-wait env=develop
	# wait and log on relevant services
	${MAKE} run env=develop services='app webserver worker worker-slow worker-nassl'
	# shut everything down
	${MAKE} down env=develop

# same as develop, but focus on frontend only
develop_frontend:
	# only bring up what is needed for frontend development
	${MAKE} build run env=develop services='app webserver port-expose'
	# shut everything down
	${MAKE} down env=develop
