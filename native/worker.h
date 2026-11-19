// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "../libfprint/biometric-ipc.h"

/* Called with a validated request from fold_bio_accept. Takes both fds. */
int x1fold_serve_request (struct fold_bio_frame frame, int channel, int hid);
