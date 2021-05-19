HASH := $(shell git rev-parse --short HEAD)
COMMIT_DATE := $(shell git show -s --format=%ci ${HASH})
BUILD_DATE := $(shell date '+%Y-%m-%d %H:%M:%S')
VERSION := ${HASH} (${COMMIT_DATE})

BUILDDIR ?= .
SRCDIR ?= .

.PHONY: help
help:
	@echo "make [TARGETS...]"
	@echo
	@echo "This is the maintenance makefile of cloud-network-setup. The following"
	@echo "targets are available:"
	@echo
	@echo "    help:               Print this usage information."
	@echo "    build:              Builds project"
	@echo "    install:            Installs binary, configuration and unit files"
	@echo "    clean:              Cleans the build"

$(BUILDDIR)/:
	mkdir -p "$@"

$(BUILDDIR)/%/:
	mkdir -p "$@"

.PHONY: build
build:
	- mkdir bin
	go build -ldflags="-X 'main.buildVersion=${VERSION}' -X 'main.buildDate=${BUILD_DATE}'" -o bin/cloud-network-setup ./cmd/cloud-network-setup
	go build -ldflags="-X 'main.buildVersion=${VERSION}' -X 'main.buildDate=${BUILD_DATE}'" -o bin/cnctl ./cmd/cnctl/

.PHONY: install
install:
	install bin/cloud-network-setup /usr/bin/
	install bin/cnctl /usr/bin

	install -vdm 755 /etc/cloud-network-setup
	install -m 755 distribution/cloud-network.toml /etc/cloud-network-setup

	install -m 0644 distribution/cloud-network-setup.service /lib/systemd/system/
	systemctl daemon-reload

PHONY: clean
clean:
	go clean
	rm -rf bin
