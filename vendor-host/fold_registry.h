#ifndef X1FOLD_REGISTRY_H
#define X1FOLD_REGISTRY_H

#include "fold_store.h"

/* Install after tudor_init and before discovery on the real device. The
   caller holds the private directory lock throughout the guest's lifetime. */
bool fold_registry_install(struct fold_store *);
#endif
