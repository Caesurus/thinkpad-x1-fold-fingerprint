// SPDX-License-Identifier: LGPL-2.1-or-later
#define _GNU_SOURCE
#include "biometric-ipc.h"
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define BROKER_DIR "/run/x1fold-fingerprint"
#define BROKER_PATH BROKER_DIR "/helper.sock"
_Static_assert(sizeof(struct fold_bio_frame) == 48, "biometric protocol frame size");

static int fail(int err) {
    errno = err;
    return -1;
}

static int64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool nonzero(const uint8_t *bytes, size_t size) {
    for (size_t i = 0; i < size; i++) if (bytes[i]) return true;
    return false;
}

static int random_id(uint8_t bytes[16]) {
    size_t done = 0;
    while (done < 16) {
        ssize_t n = getrandom(bytes + done, 16 - done, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        done += n;
    }
    return nonzero(bytes, 16) ? 0 : fail(EIO);
}

int fold_bio_new_guid(uint8_t guid[16]) {
    return guid ? random_id(guid) : fail(EINVAL);
}

static bool valid_request(const struct fold_bio_frame *f) {
    return !memcmp(f->magic, "X1WB", 4) && f->version == 1 &&
           (f->op == FOLD_ENROLL || f->op == FOLD_VERIFY || f->op == FOLD_DELETE) &&
           f->event == FOLD_BEGIN &&
           !f->stage && !f->print.reserved && f->print.finger >= 1 && f->print.finger <= 10 &&
           nonzero(f->transaction, 16) && nonzero(f->print.guid, 16) && nonzero(f->print.serial, 6);
}

static int wait_socket(int fd, short events, int cancel, int64_t deadline) {
    struct pollfd fds[] = {{fd, events, 0}, {cancel, POLLIN, 0}};
    for (;;) {
        int64_t now = now_ms();
        if (now < 0) return -1;
        int64_t left = deadline - now;
        if (left <= 0) return fail(ETIMEDOUT);
        int rc = poll(fds, 2, left > INT_MAX ? INT_MAX : (int)left);
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0) return -1;
        if (!rc) return fail(ETIMEDOUT);
        if (fds[1].revents) return fail(ECANCELED);
        if (fds[0].revents & events) return 0;
        return fail(ECONNRESET);
    }
}

static int unix_seqpacket(int fd) {
    struct sockaddr_un addr;
    socklen_t n = sizeof addr;
    int type;
    if (getpeername(fd, (struct sockaddr *)&addr, &n) < 0) return -1;
    if (addr.sun_family != AF_UNIX) return fail(EPROTOTYPE);
    n = sizeof type;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &n)) return -1;
    return type == SOCK_SEQPACKET ? 0 : fail(EPROTOTYPE);
}

static int root_peer(int fd, pid_t *pid) {
    struct ucred peer;
    socklen_t n = sizeof peer;
    if (unix_seqpacket(fd) || getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &n)) return -1;
    if (n != sizeof peer || peer.uid != 0 || peer.pid <= 0) return fail(EACCES);
    if (pid) *pid = peer.pid;
    return 0;
}

static int connect_broker(void) {
    struct stat st;
    if (lstat(BROKER_DIR, &st)) return -1;
    if (!S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022)) return fail(EACCES);
    if (lstat(BROKER_PATH, &st)) return -1;
    if (!S_ISSOCK(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0077)) return fail(EACCES);
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr = {.sun_family = AF_UNIX, .sun_path = BROKER_PATH};
    if (!connect(fd, (const struct sockaddr *)&addr, sizeof addr) && !root_peer(fd, NULL)) return fd;
    int saved = errno;
    close(fd);
    return fail(saved);
}

static int send_handoff(int fd, const struct fold_bio_frame *request, int channel, int hidraw) {
    struct iovec iov = {(void *)request, sizeof(*request)};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int) * 2)]; } control = {0};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.bytes,
                         .msg_controllen = sizeof control.bytes};
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int) * 2);
    int fds[] = {channel, hidraw};
    memcpy(CMSG_DATA(c), fds, sizeof fds);
    ssize_t n = sendmsg(fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (n < 0) return -1;
    return n == sizeof(*request) ? 0 : fail(EPROTO);
}

/* recvmsg also installs any received SCM_RIGHTS fds on malformed frames.
 * Drain and close every one which is not deliberately handed to the caller. */
static int receive(int fd, struct fold_bio_frame *frame, int *fds, size_t wanted) {
    struct iovec iov = {frame, sizeof(*frame)};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int) * 2)]; } control = {0};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.bytes,
                         .msg_controllen = sizeof control.bytes};
    ssize_t n = recvmsg(fd, &msg, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
    if (n < 0) return -1;
    size_t count = 0;
    bool valid = n == sizeof(*frame) && !(msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) {
            valid = false;
            continue;
        }
        size_t len = c->cmsg_len - CMSG_LEN(0);
        if (len % sizeof(int)) valid = false;
        for (size_t i = 0; i < len / sizeof(int); i++) {
            int received;
            memcpy(&received, CMSG_DATA(c) + i * sizeof(int), sizeof received);
            if (count < wanted) fds[count++] = received;
            else {
                valid = false;
                close(received);
            }
        }
    }
    if (valid && count == wanted) return 0;
    for (size_t i = 0; i < count; i++) close(fds[i]);
    return fail(n == 0 ? ECONNRESET : EPROTO);
}

void fold_bio_close(struct fold_bio_session *s) {
    if (s && s->socket >= 0) {
        shutdown(s->socket, SHUT_RDWR);
        close(s->socket);
        s->socket = -1;
    }
}

int fold_bio_start(struct fold_bio_session *s, enum fold_bio_operation op,
                   const struct fold_bio_identity *print, int hidraw, int cancel_fd) {
    if (!s) return fail(EINVAL);
    *s = (struct fold_bio_session){.socket = -1};
    if (!print || (op != FOLD_ENROLL && op != FOLD_VERIFY && op != FOLD_DELETE)) return fail(EINVAL);
    s->request = (struct fold_bio_frame){.magic = {'X','1','W','B'}, .version = 1, .op = op, .print = *print};
    if (random_id(s->request.transaction)) return -1;
    if (!valid_request(&s->request) || hidraw < 0) return fail(EINVAL);
    int control = connect_broker();
    if (control < 0) return -1;
    int pair[2] = {-1,-1};
    int64_t now = now_ms();
    int rc = -1;
    if (now >= 0 && !socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, pair) &&
        !wait_socket(control, POLLOUT, cancel_fd, now + 3000) &&
        !send_handoff(control, &s->request, pair[1], hidraw)) {
        s->socket = pair[0];
        s->deadline_ms = now + (op == FOLD_ENROLL ? 120000 : 30000);
        rc = 0;
    }
    int saved = errno;
    close(control);
    if (pair[1] >= 0) close(pair[1]);
    if (rc && pair[0] >= 0) close(pair[0]);
    return rc ? fail(saved) : 0;
}

int fold_bio_accept(int rendezvous, struct fold_bio_frame *request, int *channel, int *hidraw) {
    if (!request || !channel || !hidraw) return fail(EINVAL);
    *channel = *hidraw = -1;
    int64_t now = now_ms();
    pid_t client_pid, channel_pid;
    if (now < 0 || root_peer(rendezvous, &client_pid) || wait_socket(rendezvous, POLLIN, -1, now + 3000)) return -1;
    int fds[2];
    if (receive(rendezvous, request, fds, 2)) return -1;
    struct stat st;
    struct sockaddr_un addr;
    socklen_t addrlen = sizeof addr;
    if (!valid_request(request) || root_peer(fds[0], &channel_pid) || client_pid != channel_pid ||
        getpeername(fds[0], (struct sockaddr *)&addr, &addrlen) ||
        addrlen != offsetof(struct sockaddr_un, sun_path) ||
        fstat(fds[1], &st) || !S_ISCHR(st.st_mode)) {
        close(fds[0]);
        close(fds[1]);
        return fail(EPROTO);
    }
    *channel = fds[0];
    *hidraw = fds[1];
    return 0;
}

int fold_bio_next(struct fold_bio_session *s, int cancel_fd, enum fold_bio_event *event) {
    if (!s || !event || s->socket < 0) return fail(EINVAL);
    *event = FOLD_ERROR;
    struct fold_bio_frame reply;
    int error = EPROTO;
    if (wait_socket(s->socket, POLLIN, cancel_fd, s->deadline_ms) ||
        receive(s->socket, &reply, NULL, 0)) {
        error = errno;
        goto invalid;
    }
    struct fold_bio_frame expected = s->request;
    expected.event = reply.event;
    expected.stage = reply.stage;
    if (memcmp(&expected, &reply, sizeof reply) || ++s->events > 256 ||
        (reply.event != FOLD_PROGRESS && reply.stage != 0)) goto invalid;
    switch (reply.event) {
    case FOLD_PROGRESS:
        if (reply.op != FOLD_ENROLL || reply.stage != s->stage + 1 || reply.stage > 32) goto invalid;
        s->stage = reply.stage;
        break;
    case FOLD_RETRY:
        if (reply.op == FOLD_DELETE) goto invalid;
        break;
    case FOLD_DELETED:
        if (reply.op != FOLD_DELETE) goto invalid;
        fold_bio_close(s);
        break;
    case FOLD_ENROLLED:
        if (reply.op != FOLD_ENROLL || !s->stage) goto invalid;
        fold_bio_close(s);
        break;
    case FOLD_MATCH:
    case FOLD_NO_MATCH:
        if (reply.op != FOLD_VERIFY) goto invalid;
        fold_bio_close(s);
        break;
    case FOLD_ERROR:
        error = EIO;
        goto invalid;
    case FOLD_CANCELLED:
        error = ECANCELED;
        goto invalid;
    default:
        goto invalid;
    }
    *event = reply.event;
    return 0;
invalid:
    fold_bio_close(s);
    return fail(error);
}
