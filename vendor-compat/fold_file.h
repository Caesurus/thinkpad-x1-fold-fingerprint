#ifndef X1FOLD_FILE_H
#define X1FOLD_FILE_H
#include <stdbool.h>
#include <stdint.h>

/* Call after fold_cm_bind on the same inherited fd. The module takes a duplicate. */
bool fold_file_bind(int fd, uint16_t usb_revision);
/* One byte-exact GET_VERSION exchange across all opens until unbind. */
bool fold_file_bind_probe(int fd, uint16_t usb_revision);
bool fold_file_bound_for_biometrics(void);
bool fold_file_saw_open(void);
bool fold_file_saw_version(void);
bool fold_file_wait_version(unsigned timeout_ms);
void fold_file_unbind(void);

#endif
