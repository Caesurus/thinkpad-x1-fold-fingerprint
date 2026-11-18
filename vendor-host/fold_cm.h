#ifndef X1FOLD_CM_H
#define X1FOLD_CM_H

#include <stdbool.h>

/* Register the inherited hidraw fd in a single-device guest process, before
   starting its WDF threads. The caller keeps the fd open for that lifetime. */
bool fold_cm_bind(int fd);
const char *fold_cm_hid_path(void);
const char *fold_cm_biometric_id(void);
#ifdef X1FOLD_OFFLINE_PNP
void fold_cm_offline_fixture(void);
#endif

#endif
