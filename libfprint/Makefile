BUILD_DIR ?= build
PKG_CONFIG ?= pkg-config
PYTHON ?= /usr/bin/python3
UMOCKDEV_WRAPPER ?= umockdev-wrapper
DRIVER_PACKAGES = libfprint-2-tod-1 libfprint-2 gudev-1.0 gio-2.0
DRIVER_CFLAGS = $(shell $(PKG_CONFIG) --cflags $(DRIVER_PACKAGES))
DRIVER_LIBS = $(shell $(PKG_CONFIG) --libs $(DRIVER_PACKAGES))
CLIENT_CFLAGS = $(shell $(PKG_CONFIG) --cflags libfprint-2)
CLIENT_LIBS = $(shell $(PKG_CONFIG) --libs libfprint-2)
WARNINGS = -Wall -Wextra -Wno-unused-parameter
PRIVATE_DRIVER = FP_TOD_DRIVERS_DIR="$(abspath $(BUILD_DIR))" FP_DRIVERS_ALLOWLIST=x1fold_hid
.PHONY: all check discover open

all: $(BUILD_DIR)/libx1fold-hid.so $(BUILD_DIR)/x1fold-probe

$(BUILD_DIR):
	mkdir -p "$@"

$(BUILD_DIR)/libx1fold-hid.so: x1fold.c transport.c transport.h print-identity.c print-identity.h biometric-ipc.c biometric-ipc.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -fPIC -shared -DG_LOG_DOMAIN='"x1fold_hid"' $(DRIVER_CFLAGS) x1fold.c transport.c print-identity.c biometric-ipc.c $(LDFLAGS) -Wl,-z,defs $(DRIVER_LIBS) -o "$@"

$(BUILD_DIR)/x1fold-probe: probe.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(CLIENT_CFLAGS) probe.c $(LDFLAGS) $(CLIENT_LIBS) -o "$@"

$(BUILD_DIR)/test-biometric-ipc: tests/biometric-ipc.c biometric-ipc.c biometric-ipc.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) tests/biometric-ipc.c $(LDFLAGS) -o "$@"

$(BUILD_DIR)/test-print-identity: tests/print-identity.c print-identity.c print-identity.h biometric-ipc.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(DRIVER_CFLAGS) tests/print-identity.c print-identity.c $(LDFLAGS) $(DRIVER_LIBS) -o "$@"

check: all $(BUILD_DIR)/test-biometric-ipc $(BUILD_DIR)/test-print-identity
	$(BUILD_DIR)/test-biometric-ipc
	$(PRIVATE_DRIVER) FP_TOD_KEEP_MODULES_OPEN=TRUE $(UMOCKDEV_WRAPPER) $(PYTHON) tests/device.py -v

discover: all
	$(PRIVATE_DRIVER) $(BUILD_DIR)/x1fold-probe

open: all
	$(PRIVATE_DRIVER) G_MESSAGES_DEBUG=x1fold_hid $(BUILD_DIR)/x1fold-probe --open
