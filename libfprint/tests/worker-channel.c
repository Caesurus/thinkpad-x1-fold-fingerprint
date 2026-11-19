// SPDX-License-Identifier: LGPL-2.1-or-later
/* Supply a socketpair in place of the root broker for the cancellation test. */
#include "../biometric-ipc.h"
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>

int fold_bio_start(struct fold_bio_session *s, enum fold_bio_operation op,
                   const struct fold_bio_identity *print, int hid, int cancel_fd)
{
    const char *fd = getenv("X1FOLD_TEST_CHANNEL");
    if (!fd)
        return -1;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    *s = (struct fold_bio_session){
        .socket = atoi(fd),
        .deadline_ms = now.tv_sec * 1000 + now.tv_nsec / 1000000 + 30000,
        .request = {.magic = {'X','1','W','B'}, .version = 1, .op = op, .print = *print}
    };
    return send(s->socket, &s->request, sizeof s->request, MSG_NOSIGNAL) == sizeof s->request ? 0 : -1;
}
