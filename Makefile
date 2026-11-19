BUILD_DIR ?= $(CURDIR)/build
TUDOR ?= $(CURDIR)/.deps/synaTudor
LENOVO ?= $(CURDIR)/.deps/n3lgf05w.exe
PYTHON ?= /usr/bin/python3

.PHONY: all driver worker legacy check check-legacy
all: driver native-worker

legacy: driver worker

driver:
	$(MAKE) -C libfprint BUILD_DIR="$(abspath $(BUILD_DIR))" "$(abspath $(BUILD_DIR))/libx1fold-hid.so"

worker:
	$(PYTHON) -I -B vendor-host/build_worker.py "$(TUDOR)" "$(LENOVO)" --output "$(BUILD_DIR)/worker"

check:
	$(MAKE) -C libfprint BUILD_DIR="$(abspath $(BUILD_DIR))" check

check-legacy: check
	$(PYTHON) -B -m unittest discover -s vendor-host -p test_console_session.py

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
	$(MAKE) -C libfprint BUILD_DIR="$(abspath $(BUILD_DIR))" "$(abspath $(BUILD_DIR))/native-register" "$(abspath $(BUILD_DIR))/test-host-storage" "$(abspath $(BUILD_DIR))/test-worker"
	$(PYTHON) -B tests/dll-parity.py "$$FOLD_TEST_DLL_DIR" "$(abspath $(BUILD_DIR))"
