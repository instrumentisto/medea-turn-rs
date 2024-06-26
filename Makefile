###############################
# Common defaults/definitions #
###############################

comma := ,

# Checks two given strings for equality.
eq = $(if $(or $(1),$(2)),$(and $(findstring $(1),$(2)),\
                                $(findstring $(2),$(1))),1)




###########
# Aliases #
###########

all: fmt lint test.unit


docs: cargo.doc


fmt: cargo.fmt


lint: cargo.lint


test: test.unit




##################
# Cargo commands #
##################

cargo-crate = $(if $(call eq,$(crate),),--workspace,-p $(crate))


# Generate crates documentation from Rust sources.
#
# Usage:
#	make cargo.doc [crate=<crate-name>] [private=(yes|no)]
#	               [open=(yes|no)] [clean=(no|yes)]

cargo.doc:
ifeq ($(clean),yes)
	@rm -rf target/doc/
endif
	cargo doc $(cargo-crate) --all-features \
		$(if $(call eq,$(private),no),,--document-private-items) \
		$(if $(call eq,$(open),no),,--open)


# Format Rust sources with rustfmt.
#
# Usage:
#	make cargo.fmt [check=(no|yes)]

cargo.fmt:
	cargo +nightly fmt --all $(if $(call eq,$(check),yes),-- --check,)


# Lint Rust sources with Clippy.
#
# Usage:
#	make cargo.lint [crate=<crate-name>]

cargo.lint:
	cargo clippy $(cargo-crate) --all-features -- -D warnings




####################
# Testing commands #
####################


# Run project unit tests.
#
# Usage:
#	make test.unit [crate=<crate-name>] [careful=(no|yes)]

test.unit:
ifeq ($(careful),yes)
ifeq ($(shell cargo install --list | grep cargo-careful),)
	cargo install cargo-careful
endif
ifeq ($(shell rustup component list --toolchain=nightly \
              | grep 'rust-src (installed)'),)
	rustup component add --toolchain=nightly rust-src
endif
endif
	cargo $(if $(call eq,$(careful),yes),+nightly careful,) test --all-features




##################
# .PHONY section #
##################

.PHONY: all docs mt lint test \
        cargo.doc cargo.fmt cargo.lint \
        test.unit
