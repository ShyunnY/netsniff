CARGO = cargo
LOG_TARGET = echo "\033[0;32m===========> Running $@ ... \033[0m"

.PHONY: all
all: release

.PHONY: build
build:
	@$(LOG_TARGET)
	$(CARGO) build

.PHONY: release
release: clean fix check
	@$(LOG_TARGET)
	$(CARGO) build --release

.PHONY: clean
clean:
	@$(LOG_TARGET)
	$(CARGO) clean

.PHONY: check
check:
	@$(LOG_TARGET)
	$(CARGO) check

.PHONY: fix
fix:
	@$(LOG_TARGET)
	$(CARGO) clippy --fix --allow-dirty
	$(CARGO) fmt
