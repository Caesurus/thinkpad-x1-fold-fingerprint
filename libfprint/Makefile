BUILD_DIR ?= build
PKG_CONFIG ?= pkg-config
PYTHON ?= /usr/bin/python3
UMOCKDEV_WRAPPER ?= umockdev-wrapper
DRIVER_PACKAGES = libfprint-2-tod-1 libfprint-2 gudev-1.0 gio-2.0
DRIVER_CFLAGS = $(shell $(PKG_CONFIG) --cflags $(DRIVER_PACKAGES))
DRIVER_LIBS = $(shell $(PKG_CONFIG) --libs $(DRIVER_PACKAGES))
GIO_CFLAGS = $(shell $(PKG_CONFIG) --cflags gio-2.0)
GIO_LIBS = $(shell $(PKG_CONFIG) --libs gio-2.0)
CRYPTO_LIBS ?= -lcrypto
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

$(BUILD_DIR)/test-transport: tests/transport.c transport.c transport.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(GIO_CFLAGS) tests/transport.c transport.c $(LDFLAGS) $(GIO_LIBS) -o "$@"

check: all $(BUILD_DIR)/test-session $(BUILD_DIR)/test-host-proof $(BUILD_DIR)/test-handshake $(BUILD_DIR)/test-certificate $(BUILD_DIR)/test-transport $(BUILD_DIR)/test-biometric-ipc $(BUILD_DIR)/test-print-identity
	$(PYTHON) -B ../native/test-session.py "$(BUILD_DIR)/test-session"
	$(BUILD_DIR)/test-host-proof
	$(BUILD_DIR)/test-handshake
	$(BUILD_DIR)/test-certificate
	$(BUILD_DIR)/test-transport
	$(BUILD_DIR)/test-biometric-ipc
	$(PRIVATE_DRIVER) FP_TOD_KEEP_MODULES_OPEN=TRUE $(UMOCKDEV_WRAPPER) $(PYTHON) tests/device.py -v

discover: all
	$(PRIVATE_DRIVER) $(BUILD_DIR)/x1fold-probe

open: all
	$(PRIVATE_DRIVER) G_MESSAGES_DEBUG=x1fold_hid $(BUILD_DIR)/x1fold-probe --open

$(BUILD_DIR)/transport.o: transport.c transport.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -fPIC $(GIO_CFLAGS) -c $< -o "$@"

$(BUILD_DIR)/sensor-certificate.o: ../native/sensor-certificate.c ../native/sensor-certificate.h transport.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -fPIC $(GIO_CFLAGS) -c $< -o "$@"

$(BUILD_DIR)/host-proof.o: ../native/host-proof.c ../native/host-proof.h ../native/handshake.h transport.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -fPIC $(GIO_CFLAGS) -c $< -o "$@"

$(BUILD_DIR)/handshake.o: ../native/handshake.c ../native/handshake.h transport.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -fPIC $(GIO_CFLAGS) -c $< -o "$@"

$(BUILD_DIR)/test-host-proof: ../native/test-host-proof.c $(BUILD_DIR)/libx1fold-native.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(GIO_CFLAGS) $^ $(LDFLAGS) $(GIO_LIBS) $(CRYPTO_LIBS) -o "$@"

$(BUILD_DIR)/test-handshake: ../native/test-handshake.c $(BUILD_DIR)/libx1fold-native.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(GIO_CFLAGS) $^ $(LDFLAGS) $(GIO_LIBS) $(CRYPTO_LIBS) -o "$@"

$(BUILD_DIR)/capture.o: ../native/capture.c ../native/capture.h ../native/session.h ../native/sensor-certificate.h transport.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -fPIC $(GIO_CFLAGS) -c $< -o "$@"

$(BUILD_DIR)/session.o: ../native/session.c ../native/session.h ../native/sensor-certificate.h ../native/host-proof.h ../native/handshake.h transport.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -fPIC $(GIO_CFLAGS) -c $< -o "$@"

$(BUILD_DIR)/test-session: ../native/test-session.c $(BUILD_DIR)/libx1fold-native.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(GIO_CFLAGS) $^ $(LDFLAGS) -Wl,--wrap=x1fold_sensor_public_key,--wrap=x1fold_session_status,--wrap=ioctl $(GIO_LIBS) $(CRYPTO_LIBS) -o "$@"

$(BUILD_DIR)/libx1fold-native.a: $(BUILD_DIR)/capture.o $(BUILD_DIR)/session.o $(BUILD_DIR)/transport.o $(BUILD_DIR)/sensor-certificate.o $(BUILD_DIR)/handshake.o $(BUILD_DIR)/host-proof.o
	$(AR) rcs "$@" $^

$(BUILD_DIR)/native-inspect: ../native/inspect.c $(BUILD_DIR)/libx1fold-native.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(GIO_CFLAGS) $^ $(LDFLAGS) $(GIO_LIBS) $(CRYPTO_LIBS) -o "$@"

$(BUILD_DIR)/test-certificate: ../native/test-certificate.c $(BUILD_DIR)/libx1fold-native.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(GIO_CFLAGS) $^ $(LDFLAGS) $(GIO_LIBS) $(CRYPTO_LIBS) -o "$@"
