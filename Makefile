BUILD_DIR ?= $(CURDIR)/build
TUDOR ?= $(CURDIR)/.deps/synaTudor
LENOVO ?= $(CURDIR)/.deps/n3lgf05w.exe
PYTHON ?= /usr/bin/python3

.PHONY: all driver worker check
all: driver worker

driver:
	$(MAKE) -C libfprint BUILD_DIR="$(abspath $(BUILD_DIR))" "$(abspath $(BUILD_DIR))/libx1fold-hid.so"

worker:
	$(PYTHON) -I -B vendor-host/build_worker.py "$(TUDOR)" "$(LENOVO)" --output "$(BUILD_DIR)/worker"

check:
	$(MAKE) -C libfprint BUILD_DIR="$(abspath $(BUILD_DIR))" check
	$(PYTHON) -B -m unittest discover -s vendor-host -p test_console_session.py
