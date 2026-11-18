#ifndef X1FOLD_STORE_H
#define X1FOLD_STORE_H

#include <stdbool.h>
#include <stddef.h>

/* The trusted parent opens and passes the private state directory, and supplies
   the six-byte serial from the validated Tudor version reply. */
struct fold_store { int directory, lock; unsigned char serial[6]; };
enum fold_store_scope { FOLD_USER_PAIRING, FOLD_DEVICE_PROPERTY };
bool fold_store_open(struct fold_store *, int directory, const unsigned char serial[6]);
void fold_store_close(struct fold_store *);
bool fold_store_write(struct fold_store *, const char *value, const void *data, size_t size);
/* Returns a buffer owned by the caller. Use fold_protection_free on success. */
enum fold_read { FOLD_READ_ERROR = -1, FOLD_READ_MISSING, FOLD_READ_OK };
enum fold_read fold_store_read(struct fold_store *, const char *value, unsigned char **data, size_t *size);
bool fold_store_write_at(struct fold_store *, enum fold_store_scope, const char *value,
                         const void *data, size_t size);
enum fold_read fold_store_read_at(struct fold_store *, enum fold_store_scope, const char *value,
                                  unsigned char **data, size_t *size);

#endif
