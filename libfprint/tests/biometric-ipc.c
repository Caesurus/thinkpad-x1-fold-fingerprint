// SPDX-License-Identifier: LGPL-2.1-or-later
/* Private wire tests also exercise ancillary-data cleanup. None of these
 * fixtures generates an accepted enrollment or match. */
#define _GNU_SOURCE
#include <sys/stat.h>
#include <errno.h>
/* Keep request-start tests off the installed system broker. */
static int missing_broker(const char *path, struct stat *st) {
    errno = ENOENT;
    return -1;
}
#define lstat missing_broker
#include "../biometric-ipc.c"
#undef lstat
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>

static int fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    assert(d);
    int n = 0;
    while (readdir(d)) n++;
    closedir(d);
    return n;
}

static struct fold_bio_session session(int *peer, uint8_t op) {
    int pair[2];
    assert(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair));
    struct fold_bio_session s = {.socket = pair[0], .deadline_ms = now_ms() + 3000};
    s.request = (struct fold_bio_frame){.magic = {'X','1','W','B'}, .version = 1, .op = op,
        .print = {.serial = {1,2,3,4,5,6}, .finger = 2}};
    assert(!fold_bio_new_guid(s.request.print.guid) && !random_id(s.request.transaction));
    *peer = pair[1];
    return s;
}

static void reject_reply(struct fold_bio_session *s, int peer, struct fold_bio_frame reply) {
    assert(send(peer, &reply, sizeof reply, MSG_NOSIGNAL) == sizeof reply);
    enum fold_bio_event event;
    assert(fold_bio_next(s, -1, &event) == -1 && errno == EPROTO && event == FOLD_ERROR);
    assert(s->socket == -1 && read(peer, &reply, sizeof reply) == 0);
    close(peer);
}

int main(void) {
    int peer, baseline = fd_count();
    struct fold_bio_session s = session(&peer, FOLD_VERIFY);
    struct fold_bio_session outgoing;
    assert(fold_bio_start(&outgoing, FOLD_DELETE, &s.request.print, peer, -1) == -1 &&
           errno == ENOENT && outgoing.socket == -1);
    struct fold_bio_frame reply = s.request;
    reply.event = FOLD_MATCH;
    reply.print.guid[0] ^= 1;
    reject_reply(&s, peer, reply);

    s = session(&peer, FOLD_VERIFY);
    reply = s.request;
    reply.event = FOLD_MATCH;
    reply.print.serial[0] ^= 1;
    reject_reply(&s, peer, reply);

    s = session(&peer, FOLD_VERIFY);
    reply = s.request;
    reply.print.finger = 8;
    reply.event = FOLD_MATCH;
    reject_reply(&s, peer, reply);

    s = session(&peer, FOLD_VERIFY);
    reply = s.request;
    reply.transaction[7] ^= 1;
    reply.event = FOLD_MATCH;
    reject_reply(&s, peer, reply);

    s = session(&peer, FOLD_VERIFY);
    reply = s.request;
    reply.event = FOLD_ENROLLED;
    reject_reply(&s, peer, reply);

    s = session(&peer, FOLD_ENROLL);
    reply = s.request;
    reply.event = FOLD_ENROLLED;
    reject_reply(&s, peer, reply);

    s = session(&peer, FOLD_ENROLL);
    reply = s.request;
    reply.event = FOLD_PROGRESS;
    reply.stage = 2;
    reject_reply(&s, peer, reply);

    s = session(&peer, FOLD_VERIFY);
    reply = s.request;
    reply.event = FOLD_ERROR;
    assert(write(peer, &reply, sizeof reply) == sizeof reply);
    enum fold_bio_event event;
    assert(fold_bio_next(&s, -1, &event) == -1 && errno == EIO && event == FOLD_ERROR && s.socket == -1);
    close(peer);

    s = session(&peer, FOLD_VERIFY);
    reply = s.request;
    reply.event = FOLD_NO_MATCH;
    assert(write(peer, &reply, sizeof reply) == sizeof reply);
    assert(!fold_bio_next(&s, -1, &event) && event == FOLD_NO_MATCH && s.socket == -1);
    close(peer);

    s = session(&peer, FOLD_DELETE);
    reply = s.request;
    reply.event = FOLD_DELETED;
    assert(write(peer, &reply, sizeof reply) == sizeof reply);
    assert(!fold_bio_next(&s, -1, &event) && event == FOLD_DELETED && s.socket == -1);
    close(peer);

    s = session(&peer, FOLD_VERIFY);
    reply = s.request;
    reply.event = FOLD_DELETED;
    reject_reply(&s, peer, reply);

    s = session(&peer, FOLD_DELETE);
    reply = s.request;
    reply.event = FOLD_MATCH;
    reject_reply(&s, peer, reply);

    s = session(&peer, FOLD_VERIFY);
    unsigned char oversized[sizeof(reply) + 1] = {0};
    memcpy(oversized, &s.request, sizeof reply);
    assert(write(peer, oversized, sizeof oversized) == sizeof oversized);
    assert(fold_bio_next(&s, -1, &event) == -1 && errno == EPROTO && event == FOLD_ERROR);
    close(peer);

    /* A queued reply must lose to a simultaneous cancel. */
    s = session(&peer, FOLD_VERIFY);
    int cancel[2];
    assert(!pipe2(cancel, O_CLOEXEC));
    assert(write(cancel[1], "c", 1) == 1);
    reply = s.request;
    reply.event = FOLD_MATCH;
    assert(write(peer, &reply, sizeof reply) == sizeof reply);
    assert(fold_bio_next(&s, cancel[0], &event) == -1 && errno == ECANCELED && event == FOLD_ERROR);
    close(cancel[0]); close(cancel[1]); close(peer);

    s = session(&peer, FOLD_VERIFY);
    s.deadline_ms = now_ms();
    assert(fold_bio_next(&s, -1, &event) == -1 && errno == ETIMEDOUT && event == FOLD_ERROR);
    close(peer);

    s = session(&peer, FOLD_VERIFY);
    int fds[2], standin = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(standin >= 0);
    assert(!send_handoff(peer, &s.request, peer, standin));
    assert(!receive(s.socket, &reply, fds, 2) && !memcmp(&reply, &s.request, sizeof reply));
    assert((fcntl(fds[0], F_GETFD) & FD_CLOEXEC) && (fcntl(fds[1], F_GETFD) & FD_CLOEXEC));
    close(fds[0]); close(fds[1]);
    assert(!send_handoff(peer, &s.request, peer, standin));
    assert(fold_bio_next(&s, -1, &event) == -1 && errno == EPROTO && event == FOLD_ERROR);
    close(standin); close(peer);

    s = session(&peer, FOLD_ENROLL);
    if (geteuid() != 0) {
        int channel, raw;
        assert(fold_bio_accept(s.socket, &reply, &channel, &raw) == -1 && errno == EACCES);
        assert(channel == -1 && raw == -1);
    }
    fold_bio_close(&s); close(peer);
    assert(fd_count() == baseline);
    puts("Biometric IPC rejection, identity, cancellation, deadline and fd handoff tests passed.");
}
