// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include <stddef.h>

/* Trusted host startup only, before loading the guest or starting threads.
 * fd = -1 enables only process-local protection. The caller retains the fd. */
int fold_protection_start(int credential_fd);
int fold_protection_start_systemd(void);

/* 1 MiB plaintext maximum. The caller supplies a nonempty purpose (up to
 * 128 bytes) identifying the registry record. On success the caller owns
 * the allocation. On error outputs are cleared. */
int fold_protection_seal_record(const char *purpose, const void *input, size_t size,
                                unsigned char **out, size_t *out_size);
int fold_protection_unseal_record(const char *purpose, const void *input, size_t size,
                                  unsigned char **out, size_t *out_size);
void fold_protection_free(void *data, size_t size);
