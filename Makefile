# Makefile for Phantom apps CI
#  created oct-2018 by rbraun at splunk
#
# Usage:
#   make local     - to bring up docker for local dev
#   make <target>  - pipeline targets build / upload
#   make secrets   - list any required secret values
#
# Credentials can be passed as environment variables or docker secret files
# under /run/secrets


# Variables set by GitLab
WORKSPACE          ?= $(shell pwd)
CI_COMMIT_REF_NAME ?= $(shell git branch | grep "\*" | cut -d ' ' -f 2)

# Git variables
GIT_SERVER         ?= cd.splunkdev.com
RELEASE_GROUP      ?= phantom
RELEASE_REPO       ?= app_release

# Docker variables
DOCKER_WORK               ?= $(shell grep :/build local/docker-compose.yml | cut -d : -f 2)
export IMAGE_TAG          ?= $(shell grep ^image: .gitlab-ci.yml | cut -d : -f 3)

# Variables sent to app_release for test/build/release scripts
export APP_DIR           ?= $(WORKSPACE)
export APP_REPO_NAME     ?= $(shell basename `pwd`)
export APP_BRANCH        ?= $(CI_COMMIT_REF_NAME)
export TEST_BRANCH       ?= master

# Pipeline secrets
SECRETS = artifactory_token gitlab_api_token app_deploy_key
ifneq ($(wildcard /run/secrets/.),)
 # Load secrets if specified in filesystem rather than variables
 export GITLAB_API_TOKEN  ?= $(shell cat /run/secrets/gitlab_api_token)
 export ARTIFACTORY_TOKEN := $(shell cat /run/secrets/artifactory_token)
 export APP_DEPLOY_KEY    := $(shell cat /run/secrets/app_deploy_key)
endif

.PHONY: checkout test upload build release local secrets list_secrets

checkout: $(WORKSPACE)/$(RELEASE_REPO)
$(WORKSPACE)/$(RELEASE_REPO): /tmp/ssh-agent
	@echo Clone the $(RELEASE_REPO) repo
	@git clone git@$(GIT_SERVER):$(RELEASE_GROUP)/$(RELEASE_REPO).git
	@echo Checkout the working app branch
	@cd $(RELEASE_REPO); git checkout $(TEST_BRANCH)

test: checkout
	@cd $(RELEASE_REPO) && make $@

upload: checkout
	@cd $(RELEASE_REPO) && make $@

build: checkout
	@cd $(RELEASE_REPO) && make $@

release: checkout
	@cd $(RELEASE_REPO) && make $@

local: secrets
	@echo Setting up local development instance
	@echo Make sure you have run:
	$(info   docker login repo.splunk.com)
	(cd local; docker-compose up -d)
	@echo Working directory is mapped to $(DOCKER_WORK). To connect:
	$(info   docker exec -it -w $(DOCKER_WORK) local_qa-local_1 bash)

/tmp/ssh-agent:
	echo Starting ssh agent
	@mkdir -p -m 700 ~/.ssh
	@ssh-keyscan -p 22 $(GIT_SERVER) >> ~/.ssh/known_hosts
	@eval $(shell ssh-agent -s >$@)
	@if [ -s /run/secrets/app_deploy_key ]; then \
	  cp /run/secrets/app_deploy_key ~/.ssh/id_rsa && \
		/bin/bash -c "source $@ && ssh-add ~/.ssh/id_rsa"; \
	else \
	  cp ~/.ssh/app_deploy_key ~/.ssh/id_rsa && \
	  chmod 600 ~/.ssh/id_rsa && \
		cat $@ && \
		/bin/bash -c "source $@ && ssh-add ~/.ssh/id_rsa"; \
	fi

SECRET_FILES = $(foreach I,$(SECRETS),~/.docker/secrets/$I)
secrets: list_secrets $(SECRET_FILES)
list_secrets:
	@echo From .docker/secrets these files are loaded:
	$(info   $(SECRETS))
