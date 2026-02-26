SHELL=/bin/bash

REMOTEDATADIR=remote_data
MACSDIR=$(REMOTEDATADIR)/macs
CERTSSDIR=$(REMOTEDATADIR)/certs
DNSDIR=$(REMOTEDATADIR)/dns

# default version if nothing is provided by environment
RELEASE ?= 0.0.0-dev0

# directories used to find python sources for things like linting etc
pysrcdirs = internetnl tests interface checks integration_tests docker

# make sure these targets still run if a file with the same name exists
.PHONY: translations translations_tar frontend update_cert_fingerprints update_container_documentation update_padded_macs venv frontend clean clen_venv pip-compile pip-upgrade pip-upgrade-package pip-install run run-worker run-worker-batch-callback run-worker-batch-main run-worker-batch-scheduler run-heartbeat run-broker run-rabbit manage run-test-worker version unbound-3.10-github unbound-3.7-github nassl test check autofix integration-tests batch-tests

# as this is the first command in the makefile it will show if no argument is specified or if 'help' is specified to explain the available targets
help:           ## Show this help.
	@IFS=$$'\n' ; \
	help_lines=(`fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##/|/'`); \
	printf "\nMakefile for internet.nl.\n" ; \
	printf "\nUsage:\n\n" ; \
	printf "%-30s %s\n" "target" "help" ; \
	printf "%-30s %s\n" "------" "----" ; \
	for help_line in $${help_lines[@]}; do \
		IFS=$$'|' ; \
		help_split=($$help_line) ; \
		help_command=`echo $${help_split[0]} | sed -e 's/^ *//' -e 's/://' -e 's/ *$$//'` ; \
		help_info=`echo $${help_split[1]} | sed -e 's/^ *//' -e 's/ *$$//'` ; \
		printf '\033[36m'; \
		printf "%-30s %s" $$help_command ; \
		printf '\033[0m'; \
		printf "%s\n" $$help_info; \
	done; \
	printf "\nMost commands will need a 'env=x' argument to specify the environment (dev, test), eg: 'make up env=dev'"

branch ?= main
update_content: ## update the translation files from content repo, (re)generate CSS and Javascript, optional branch=x to use a specific content repo branch
    # This retrieves the content from the content repository and merges it with the .po files of this repo.
    # The procedure is detailed at: https://github.com/internetstandards/Internet.nl_content/blob/master/.README.md
	rm -rf tmp/locale_files/
	rm -f tmp/content_repo.tar.gz
	mkdir -p tmp/locale_files/
	git clone -b $(branch) git@github.com:internetstandards/Internet.nl_content/ tmp/locale_files/
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools bin/update_translations.sh
	rm -rf tmp/locale_files

update_cert_fingerprints: ## update certificate fingerprint information
	chmod +x $(CERTSSDIR)/update-certs.sh
	chmod +x $(CERTSSDIR)/mk-ca-bundle.pl
	cd $(CERTSSDIR); ./update-certs.sh

update_container_documentation: ## update container table for documentation
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools bin/update_container_documentation.sh

update_expire_sectxt_pgp_test: ## test if security.txt or PGP key needs an update
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools bin/update_expire_sectxt_pgp_test.sh

update_padded_macs: ## update padded MAC information
	chmod +x $(MACSDIR)/update-macs.sh
	cd $(MACSDIR); ./update-macs.sh

update_root_key_file: ## update root key file
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools /opt/unbound/sbin/unbound-anchor -a $(DNSDIR)/root.key

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
$(info "")
$(info A `docker/local.env` exists which may override default behaviour!)
$(info "")
$(info File contents:)
$(info "")
$(info $(shell cat docker/local.env))
$(info "")

localenv = --env-file=docker/local.env
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

# command to run in development environment
DOCKER_COMPOSE_DEVELOP_CMD=docker compose --env-file=docker/defaults.env --env-file=docker/develop.env

# command to run in test environment
DOCKER_COMPOSE_TEST_CMD=COMPOSE_FILE=docker/compose.yaml:docker/compose.test.yaml \
	docker compose ${compose_args} \
	--env-file=docker/defaults.env \
	--env-file=docker/test.env \
	${localenv}

# command to run in tools container
DOCKER_COMPOSE_TOOLS_CMD=COMPOSE_FILE=docker/compose.tools.yaml docker compose

build: ## build all docker images
	${DOCKER_COMPOSE_BUILD_CMD} build ${build_args} --build-arg=RELEASE=${RELEASE} ${services}

build-no-cache: build ## build all docker images without using cache
build-no-cache: build_args=--no-cache

up: ## bring up an environment, and keep it running in the background, use env=x for a specific environment (test, dev)
	${DOCKER_COMPOSE_UP_PULL_CMD} up --wait --no-build --remove-orphans --timeout=0 ${services}
	@if [ "${environment}" = "test" ]; then echo -e "\n🚀 Running on http://localhost:8081"; fi
	@if [ "${environment}" = "develop" ]; then echo -e "\n🚀 Running on http://localhost:8080"; fi
	@if [ "${environment}" = "batch-test" ]; then echo -e "\n🚀 Running on http://localhost:8081"; fi

up-no-wait: ## bring up an environment but don't wait for it to be ready
	${DOCKER_COMPOSE_UP_PULL_CMD} up --detach --no-build --remove-orphans --timeout=0 ${services}

run: ## bring up an environment but run it in the foreground with logging enabled, ctrl-c to bring the environment down
	${DOCKER_COMPOSE_UP_PULL_CMD} up --watch --remove-orphans --timeout=0 ${services}

restart: ## restart all services in an environment
	${DOCKER_COMPOSE_CMD} restart --no-deps ${services}

up-build-no-deps: ## (re)build images and bring environment up for only specific service (eg: make up-build-no-deps env=test services=app)
	${DOCKER_COMPOSE_UP_PULL_CMD} up --wait --build --no-deps --build-arg=RELEASE=${RELEASE} ${services}

up-no-deps: ## bring environment up for only specific service (eg: make up-no-deps env=test services=app)
	${DOCKER_COMPOSE_UP_PULL_CMD} up --wait --no-deps ${services}

ps: ## show all services/containers for the project
	${DOCKER_COMPOSE_CMD} ps

logs: services=webserver app worker worker-nassl worker-slow resolver test-target
logs: ## follow logs for most important services, used services= for specific services (eg: make logs services=app)
	${DOCKER_COMPOSE_CMD} logs --follow ${services}

logs-all: ## follow logs for all services
	${DOCKER_COMPOSE_CMD} logs --follow

logs-all-dump: ## dump all logs for all services
	${DOCKER_COMPOSE_CMD} logs

exec: service=app
exec: cmd=/bin/bash
exec: ## run a specific command in a specific service (eg: make exec env=dev service=app cmd='ls /source')
	${DOCKER_COMPOSE_CMD} exec --user root ${service} ${cmd}

run-shell: service=app
run-shell: cmd=/bin/bash
run-shell: ## start a container with a  shell to debug startup issues (eg: make run-shell env=dev cmd=bash service=app)
	${DOCKER_COMPOSE_UP_PULL_CMD} run ${run_args} --entrypoint ${cmd} ${service}

docker-compose-config: ## show result of merging .yml docker compose config files
	${DOCKER_COMPOSE_UP_PULL_CMD} config


docker-compose-config-to-file: ## dump the merged compose config to a file with the versions of docker and compose for easier comparison
	${DOCKER_COMPOSE_UP_PULL_CMD} config > "config-compose-$$(docker compose version --short)-$$(docker version -f 'server-{{.Server.Version}}-client-{{.Client.Version}}').yml"

create-superuser: ## create django superuser
	${DOCKER_COMPOSE_CMD} exec app ./manage.py shell -c "from django.contrib.auth.models import User; User.objects.create_superuser('admin', 'admin@example.com', 'admin')"

rabbitmq-admin: ## open rabbitmq admin web interface
	open "http://guest:guest@localhost:$$(${DOCKER_COMPOSE_CMD} port rabbitmq 15672)"

postgres-shell: ## open PostgresQL database shell (psql)
	${DOCKER_COMPOSE_CMD} exec postgres psql --username "internetnl" --dbname "internetnl_db1"

redis-shell: ## open Redis CLI shell (redis-cli)
	${DOCKER_COMPOSE_CMD} exec redis redis-cli

reset-test-target: ## manually reset test target cache
	curl http://localhost:8080/clear/target.test/ -s

stop: ## pause all containers, but don't remove them
	${DOCKER_COMPOSE_CMD} stop

down: ## stop and remove all containers, but keep volumes (eg: routinator cache, databases)
	${DOCKER_COMPOSE_CMD} down --timeout=0

down-remove-volumes: ## stop and remove all containers and volumes (eg: routinator cache, databases)
	${DOCKER_COMPOSE_CMD} down --volumes

docker-compose-reset: ## reset entire docker compose environment and network, warning this might effect other compose project besides internet.nl
	${DOCKER_COMPOSE_CMD} down --volumes
	docker network prune -f

pull: ## pull all docker images for the project
	${DOCKER_COMPOSE_UP_PULL_CMD} pull ${pull_args}

batch-api-create-db-indexes: ## create DB indexes for batch api
	${DOCKER_COMPOSE_CMD} exec app ./manage.py api_create_db_indexes

test-runner-shell: env=test
test-runner-shell: ## open a bash shell in a test runner container for test environment debugging
		${DOCKER_COMPOSE_UP_PULL_CMD} run --entrypoint /bin/bash test-runner

tests ?= .
integration-tests: env=test
integration-tests: ## run integration tests
	${DOCKER_COMPOSE_UP_PULL_CMD} run --rm test-runner --browser=firefox --screenshot=only-on-failure --video=retain-on-failure --junit-xml=test-results.xml ${_test_args} ${test_args} -k'${tests}' integration_tests/common/ integration_tests/integration/
	@echo -e "\nTo run with only specific tests use the 'tests' argument with part of the test's name, for example: make integration-tests tests=test_index_http_ok\n"

integration-tests-verbose: _test_args=--verbose --verbose
integration-tests-verbose: integration-tests ## run integration tests with verbose logging

integration-tests-all-browser: _test_args=--browser=firefox --browser=chromium --browser=webkit
integration-tests-all-browser: integration-tests ## run integration tests using all available browsers (firefox, chromium, webkit)

integration-tests-trace: _test_args=--tracing=retain-on-failure
integration-tests-trace: integration-tests ## run integration tests but retain Playwright trace files

batch-tests: env=batch-test
batch-tests: ## run batch tests
	${DOCKER_COMPOSE_UP_PULL_CMD} run --rm test-runner --browser=firefox --screenshot=only-on-failure --video=retain-on-failure --junit-xml=test-results.xml ${_test_args} ${test_args} -k'${tests}' integration_tests/common/ integration_tests/batch/

batch-tests-verbose: _test_args=--verbose --verbose
batch-tests-verbose: batch-tests ## run batch tests with verbose logging

batch-tests-shell: env=batch-test
batch-tests-shell: ## open a bash shell in batch test environment
	${DOCKER_COMPOSE_UP_PULL_CMD} run --entrypoint /bin/bash test-runner

live-tests: ## run live tests again a instance, eg: APP_URLS=https://internet.nl TEST_DOMAINS=https://example.nl make live-tests
	COMPOSE_FILE=docker/compose.test-runner-live.yaml RELEASE=latest docker compose run --rm test-runner-live \
		-ra --screenshot=only-on-failure --video=retain-on-failure --junit-xml=test-results.xml ${test_args} integration_tests/live/

# use OS specific hostname for Docker host
ifeq ($(shell uname -s),Darwin)
docker_host = host.docker.internal
else
docker_host = host-gateway
endif

# this runs limited live test suite against the development environment to test its sanity
develop-tests development-environment-tests: ## run development environment tests
	APP_URLS=http://${docker_host}:8080  ${DOCKER_COMPOSE_DEVELOP_CMD} run --rm test-runner-development-environment \
		-ra --screenshot=only-on-failure --video=retain-on-failure --junit-xml=test-results.xml ${test_args} -k'${tests}' integration_tests/develop/

develop-tests-shell: ## open a bash shell in development test environment
	${DOCKER_COMPOSE_DEVELOP_CMD} run --rm --entrypoint bash test-runner-development-environment


test: ## run unit tests
	${DOCKER_COMPOSE_TEST_CMD} run --rm test python3 \
	-m coverage run \
	-m pytest -vvv -ra \
	--junit-xml=test-results.xml \
	$(filter-out integration_tests,${pysrcdirs}) \
    -k'${tests}' \
	${test_args}

test-shell: ## open a bash shell in unit test environment
	${DOCKER_COMPOSE_TEST_CMD} run --rm test bash

test-all: ## run all tests on all environments
	# bring running environments down
	$(MAKE) down environment=develop
	$(MAKE) down environment=test
	$(MAKE) down environment=batch-test
	# build all images
	$(MAKE) build
	# run checks
	$(MAKE) check
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
	# run unittests
	$(MAKE) test
	$(MAKE) down environment=test

makemigrations: ## run `./manage.py makemigrations` to update Django migrations
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools env SKIP_SECRET_KEY_CHECK=True CACHE_LOCATION= ENABLE_BATCH= ./manage.py makemigrations

lint: ## run linter
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools bin/lint.sh ${pysrcdirs}

check: ## run checks (eg: shellcheck)
check: ## run checks (eg: package locks, migrations, document generation, etc)
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools bin/check.sh ${pysrcdirs}
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools bin/check.sh

fix: ## fix trivial linting error automatically
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools bin/fix.sh ${pysrcdirs}
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools bin/lint.sh ${pysrcdirs}

check-gixy: env=test
check-gixy: ## run nginx config check
	${DOCKER_COMPOSE_CMD} exec webserver /opt/gixy/bin/gixy /etc/nginx/nginx.conf

build-tools tools-build: ## build tools image
	${DOCKER_COMPOSE_TOOLS_CMD} build tools

shell tools-shell: ## open shell in tools container
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools bash

integration-tests-against-develop: _env:=${_env} INTERNETNL_USE_DOCKER_COMPOSE_PROJECT="internetnl"
integration-tests-against-develop: integration-tests ## run integration-tests against development environment instance

integration-tests-reset-and-against-develop: ## reset caches in development environment and run integration-tests against development environment instance
integration-tests-reset-and-against-develop: docker-compose-redis-clear-celery-results integration-tests-against-develop

# Docker container runtime for MacOS
# until nassl can be built for ARM: https://github.com/nabla-c0d3/nassl/issues/39
# it is required to emulate x86_64 under Apple Silicon Macs
docker-compose-runtime-start: ## start a Colima Docker runtime for development
	colima start --cpu 4 --memory 8 --arch x86_64

docker-compose-runtime-stop: ## stop Colima Docker runtime
	colima stop

images = $(patsubst %.py,%.png,$(wildcard documentation/images/*.py))
documentation-images: ## generate documentation images
documentation-images: ${images}
documentation/images/%.png: documentation/images/%.py | ${nwdiag}
	docker run -it --rm -v "$${PWD}/$(@D)/":/$(@D) -w /$(@D) gtramontina/diagrams:0.23.1 $(<F)

batch_user ?=
batch_host ?= dev-docker.batch.internet.nl
batch_api = https://${batch_host}/api/batch/v2
TMPDIR ?= /tmp

batch_submit_web_%k: ## submit an amount of domains from tranco as a web batch request to dev-docker.batch.internet.nl
batch_submit_web_1k batch_submit_web_5k batch_submit_web_10k batch_submit_web_15k batch_submit_web_20k: batch_submit_web_%k: ${TMPDIR}/batch_request_%k_web.json
	auth="${batch_user}:$$(keyring get internet.nl-batch ${batch_user})" ;\
	response=$$(curl -s -u $$auth ${batch_api}/requests -H "Content-type: application/json" -d @$<) ;\
	echo $$response ;\
	request_id=$$(echo $$response | jq .request.request_id) ;\
	watch "curl -s -u $$auth ${batch_api}/requests/$$request_id | jq .; curl -s -u $$auth ${batch_api}/requests/$$request_id/results | jq .request,.error" ;

batch_submit_mail_%k: ## submit an amount of domains from tranco as a mail batch request to dev-docker.batch.internet.nl
batch_submit_mail_1k batch_submit_mail_5k batch_submit_mail_10k batch_submit_mail_15k batch_submit_mail_20k: batch_submit_mail_%k: ${TMPDIR}/batch_request_%k_mail.json
	auth="${batch_user}:$$(keyring get internet.nl-batch ${batch_user})" ;\
	response=$$(curl -s -u $$auth ${batch_api}/requests -H "Content-type: application/json" -d @$<) ;\
	echo $$response ;\
	request_id=$$(echo $$response | jq .request.request_id) ;\
	watch "curl -s -u $$auth ${batch_api}/requests/$$request_id | jq .; curl -s -u $$auth ${batch_api}/requests/$$request_id/results | jq .request,.error" ;

${TMPDIR}/batch_request_%k_web.json: ${TMPDIR}/tranco_list_%k.txt
	# convert to json batch request file
	jq '{domains:.|split("\n")|map(select(length>0)),name:"tranco $*k - web",type:"web"}' -Rsc $< > $@

${TMPDIR}/batch_request_%k_mail.json: ${TMPDIR}/tranco_list_%k.txt
	# convert to json batch request file
	jq '{domains:.|split("\n")|map(select(length>0)),name:"tranco $*k - mail",type:"mail"}' -Rsc $< > $@

${TMPDIR}/tranco_list_%k.txt: ${TMPDIR}/tranco_list.txt
	# get first $*k of domains
	head -n$*000 $< | tr -d \r > $@

${TMPDIR}/tranco_list.txt:
	# download tranco list, unzip, convert from csv to plain list of domains
	curl -Ls https://tranco-list.eu/download_daily/4Q39X | bsdtar -xOf - | cut -d, -f2 > $@

develop: ## convenience target, will build and run all services for development and output logs for the relevant ones
	# (re)build all services
	${MAKE} build env=develop
	# bring entire environment up
	${MAKE} up-no-wait env=develop
	# wait and log on relevant services
	${MAKE} run env=develop services='app webserver worker worker-slow worker-nassl'
	# shut everything down
	${MAKE} down env=develop


develop_frontend: ## same as develop, but focus on frontend only
	# only bring up what is needed for frontend development
	${MAKE} build run env=develop services='app webserver port-expose'
	# shut everything down
	${MAKE} down env=develop

uv_lock: ## update the uv.lock file after changing pyproject.toml
	${DOCKER_COMPOSE_TOOLS_CMD} run --rm tools uv lock
