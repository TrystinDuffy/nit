SHELL := /bin/sh

CARGO ?= cargo
RUSTC ?= rustc
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=
DISTDIR ?= dist
ARGS ?=

.PHONY: all help setup doctor build run release test fmt fmt-check lint check ci install install-user dist clean tools

all: release

help:
	@printf '%s\n' \
	  'Development:' \
	  '  make setup              Install the Rust 1.87 toolchain with mise' \
	  '  make build              Build a debug binary' \
	  '  make run ARGS="..."     Run the debug binary' \
	  '  make fmt                Format Rust sources' \
	  '  make check              Format check, tests, and Clippy' \
	  '' \
	  'Release/install:' \
	  '  make release            Build target/release/nit' \
	  '  make dist               Create a host tarball under dist/' \
	  '  make ci                 Run checks and create the dist tarball' \
	  '  sudo make install       Install under /usr/local by default' \
	  '  make install-user       Install under $$HOME/.local' \
	  '' \
	  'Overrides: CARGO, RUSTC, PREFIX, BINDIR, DESTDIR, DISTDIR, ARGS'

setup:
	@command -v mise >/dev/null 2>&1 || { \
		echo 'mise is not installed; use nix develop or install Rust 1.87 manually.' >&2; \
		exit 1; \
	}
	mise install
	@$(MAKE) doctor

doctor: tools
	@$(CARGO) --version
	@$(RUSTC) --version
	@command -v pkg-config >/dev/null 2>&1 || { \
		echo 'warning: pkg-config is missing (needed to find PC/SC on Linux)' >&2; \
	}
	@if command -v pkg-config >/dev/null 2>&1; then \
		pkg-config --exists libpcsclite || \
			echo 'warning: libpcsclite development files were not found' >&2; \
	fi

tools:
	@$(CARGO) --version >/dev/null 2>&1 && $(RUSTC) --version >/dev/null 2>&1 || { \
		echo 'Rust is unavailable. Run "make setup" or "nix develop" first.' >&2; \
		exit 1; \
	}

build: tools
	$(CARGO) build --locked

run: tools
	$(CARGO) run --locked -- $(ARGS)

release: tools
	$(CARGO) build --locked --release

test: tools
	$(CARGO) test --locked

fmt: tools
	$(CARGO) fmt

fmt-check: tools
	$(CARGO) fmt --check

lint: tools
	$(CARGO) clippy --locked --all-targets --all-features -- -D warnings

check: fmt-check test lint

ci: check dist

install: release
	install -Dm755 target/release/nit "$(DESTDIR)$(BINDIR)/nit"

install-user:
	$(MAKE) install PREFIX="$(HOME)/.local"

dist: release
	@set -eu; \
	version=$$(awk -F '"' '/^version = / { print $$2; exit }' Cargo.toml); \
	host=$$($(CARGO) -Vv | awk '/^host:/ { print $$2 }'); \
	name="nit-$$version-$$host"; \
	stage=$$(mktemp -d); \
	trap 'rm -rf "$$stage"' EXIT HUP INT TERM; \
	mkdir -p "$$stage/$$name" "$(DISTDIR)"; \
	install -m755 target/release/nit "$$stage/$$name/nit"; \
	install -m644 README.md LICENSE "$$stage/$$name/"; \
	tar -C "$$stage" -czf "$(DISTDIR)/$$name.tar.gz" "$$name"; \
	printf 'Created %s\n' "$(DISTDIR)/$$name.tar.gz"

clean: tools
	$(CARGO) clean
	rm -rf "$(DISTDIR)"
