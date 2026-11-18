// SPDX-License-Identifier: LGPL-2.1-or-later
#include "worker.h"
#include <unistd.h>

int
main (void)
{
  struct fold_bio_frame frame;
  int channel, hid;
  if (!geteuid () || fold_bio_accept (STDIN_FILENO, &frame, &channel, &hid))
    return 1;
  return x1fold_serve_request (frame, channel, hid);
}
