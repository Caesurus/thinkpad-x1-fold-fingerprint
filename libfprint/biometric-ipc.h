// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include <stdint.h>

enum fold_bio_operation { FOLD_ENROLL = 1, FOLD_VERIFY = 2, FOLD_DELETE = 3 };
enum fold_bio_event {
    FOLD_BEGIN = 0, FOLD_PROGRESS = 1, FOLD_RETRY = 2, FOLD_ENROLLED = 3,
    FOLD_MATCH = 4, FOLD_NO_MATCH = 5, FOLD_ERROR = 6, FOLD_CANCELLED = 7,
    FOLD_DELETED = 8, FOLD_DUPLICATE = 9
};

/* Wire values use octets only. guid is the exact 16-byte WinBio GUID
 * representation, serial is the raw Tudor serial, finger is the WinBio
 * subfactor (right thumb through little = 1..5, left = 6..10). */
struct fold_bio_identity {
    uint8_t guid[16], serial[6], finger, reserved;
};
struct fold_bio_frame {
    uint8_t magic[4], version, op, event, stage;
    uint8_t transaction[16];
    struct fold_bio_identity print;
};
struct fold_bio_session {
    int socket;
    int64_t deadline_ms;
    struct fold_bio_frame request;
    unsigned events, stage;
};

/* Driver side. Opens only the fixed, root-managed broker endpoint. An enroll
 * caller first generates a fresh print GUID. A verify caller must supply the
 * original authenticated record identity. Cancellation fd is readable when
 * cancellation is requested; pass -1 when unavailable. */
int fold_bio_new_guid(uint8_t guid[16]);
int fold_bio_start(struct fold_bio_session *session, enum fold_bio_operation op,
                   const struct fold_bio_identity *print, int hidraw, int cancel_fd);
int fold_bio_next(struct fold_bio_session *session, int cancel_fd, enum fold_bio_event *event);
void fold_bio_close(struct fold_bio_session *session);

/* Broker side. Called with an accepted, connected Unix seqpacket socket.
 * Only requests from UID 0 are accepted. On success the caller owns both
 * descriptors; independently verify sensor identity against the opened fd
 * before sensor I/O. A match reply requires an authenticated reader result. */
int fold_bio_accept(int rendezvous, struct fold_bio_frame *request,
                    int *private_socket, int *hidraw);
