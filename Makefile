BUILD_DIR ?= $(CURDIR)/build
PYTHON ?= /usr/bin/python3

.PHONY: all driver check
all: driver native-worker

driver:
	$(MAKE) -C libfprint BUILD_DIR="$(abspath $(BUILD_DIR))" "$(abspath $(BUILD_DIR))/libx1fold-hid.so"

check:
	$(MAKE) -C libfprint BUILD_DIR="$(abspath $(BUILD_DIR))" check
	BUILD_DIR="$(abspath $(BUILD_DIR))" sh tests/stage-install.sh

.PHONY: native native-inspect native-worker native-register
native:
	$(MAKE) -C libfprint BUILD_DIR="$(abspath $(BUILD_DIR))" "$(abspath $(BUILD_DIR))/libx1fold-native.a"

native-inspect:
	$(MAKE) -C libfprint BUILD_DIR="$(abspath $(BUILD_DIR))" "$(abspath $(BUILD_DIR))/native-inspect"

native-worker:
	$(MAKE) -C libfprint BUILD_DIR="$(abspath $(BUILD_DIR))" "$(abspath $(BUILD_DIR))/native-worker"

native-register:
	$(MAKE) -C libfprint BUILD_DIR="$(abspath $(BUILD_DIR))" "$(abspath $(BUILD_DIR))/native-register"

# Optional offline differential tests; the DLLs are external test inputs.
.PHONY: check-dll
check-dll: private export FOLD_TEST_DLL_DIR := $(value DLL_DIR)
check-dll:
	@test -n "$$FOLD_TEST_DLL_DIR" || { echo "Set DLL_DIR to the extracted Fold v153 package directory" >&2; exit 2; }
	$(MAKE) -C libfprint BUILD_DIR="$(abspath $(BUILD_DIR))" "$(abspath $(BUILD_DIR))/native-register" "$(abspath $(BUILD_DIR))/test-issuer" "$(abspath $(BUILD_DIR))/test-host-storage" "$(abspath $(BUILD_DIR))/test-worker"
	$(PYTHON) -B tests/dll-parity.py "$$FOLD_TEST_DLL_DIR" "$(abspath $(BUILD_DIR))"
