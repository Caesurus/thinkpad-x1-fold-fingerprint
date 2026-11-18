#include "capture_once.h"
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/random.h>
#include <unistd.h>
#include <tudor/tudor.h>

static void capture_finished(tudor_async_res_t result, bool success, void *context)
{
    (void)result;
    (void)success;
    int fd = (int)(intptr_t)context;
    while (eventfd_write(fd, 1) < 0 && errno == EINTR) {}
}

/* A negative return distinguishes cancellation from a vendor retry. */
static int wait_for_sample(tudor_async_res_t result, int fd, int status_fd, int disconnect_fd)
{
    tudor_set_async_callback(result, capture_finished, (void *)(intptr_t)fd);
    dprintf(status_fd, "WinBio capture started. Waiting for a finger.\n");
    struct pollfd events[] = {{fd, POLLIN, 0}, {disconnect_fd, POLLIN, 0}};
    bool signalled = poll(events, 2, 60000) > 0 && !events[1].revents && (events[0].revents & POLLIN);
    if (!signalled) {
        dprintf(status_fd, "Cancelling the pending WinBio capture\n");
        tudor_cancel_async(result);
    }
    bool success = tudor_wait_async(result);
    /* The result condition precedes delivery of the completion callback. */
    eventfd_t value;
    int n;
    do {
        n = eventfd_read(fd, &value);
    } while (n < 0 && errno == EINTR);
    tudor_cleanup_async(result);
    if (!signalled || n < 0)
        return -1;
    return success ? 1 : 0;
}

static bool enroll(struct tudor_device *device, RECGUID guid, enum tudor_finger finger,
                   int status_fd, bool commit, const struct fold_capture_monitor *monitor)
{
    int fd = eventfd(0, EFD_CLOEXEC);
    if (fd < 0)
        return false;
    if (!tudor_enroll_start(device, guid, finger)) {
        dprintf(status_fd, "Could not start WinBio enrollment\n");
        close(fd);
        return false;
    }

    bool accepted = false;
    unsigned stage = 0;
    for (unsigned attempt = 0; attempt < 32; attempt++) {
        bool complete = false;
        tudor_async_res_t result = NULL;
        if (!tudor_enroll_capture(device, &complete, &result)) {
            dprintf(status_fd, "WinBio rejected the capture start\n");
            break;
        }
        int outcome = wait_for_sample(result, fd, status_fd, monitor ? monitor->disconnect_fd : -1);
        accepted = outcome == 1;
        dprintf(status_fd, "Engine accepted this sample: %s\n", accepted ? "yes" : "no");
        if (!commit || outcome < 0 || (!accepted && complete))
            break;
        if (!accepted) {
            if (monitor && !monitor->report(monitor->data, stage, true)) break;
            dprintf(status_fd, "Retry the sample\n");
            continue;
        }
        dprintf(status_fd, "Accepted enrollment sample %u\n", ++stage);
        if (monitor && !monitor->report(monitor->data, stage, false)) break;
        if (complete) {
            bool duplicate = false;
            if (tudor_enroll_commit(device, &duplicate)) {
                dprintf(status_fd, "WinBio committed the enrollment\n");
                close(fd);
                return true;
            }
            dprintf(status_fd, "WinBio commit failed, duplicate=%u\n", duplicate);
            break;
        }
    }
    bool discarded = tudor_enroll_discard(device);
    dprintf(status_fd, "Discarded temporary enrollment: %s\n", discarded ? "yes" : "no");
    close(fd);
    return !commit && accepted && discarded;
}

bool fold_capture_once(struct tudor_device *device, int status_fd)
{
    RECGUID guid;
    return device && getrandom(&guid, sizeof(guid), 0) == sizeof(guid) &&
           enroll(device, guid, TUDOR_FINGER_RH_INDEX_FINGER, status_fd, false, NULL);
}

bool fold_enroll_print(struct tudor_device *device, const uint8_t identity[16],
                       unsigned finger, int status_fd)
{
    return fold_enroll_monitored(device, identity, finger, status_fd, NULL);
}

bool fold_enroll_monitored(struct tudor_device *device, const uint8_t identity[16], unsigned finger,
                           int status_fd, const struct fold_capture_monitor *monitor)
{
    RECGUID guid;
    _Static_assert(sizeof(guid) == 16, "WinBio GUID size");
    if (!device || !identity || finger < 1 || finger > 10)
        return false;
    memcpy(&guid, identity, sizeof(guid));
    return enroll(device, guid, finger, status_fd, true, monitor);
}

enum fold_verdict fold_verify_print(struct tudor_device *device, const uint8_t identity[16],
                                    unsigned finger, int status_fd)
{
    return fold_verify_monitored(device, identity, finger, status_fd, NULL);
}

enum fold_verdict fold_verify_monitored(struct tudor_device *device, const uint8_t identity[16],
                                        unsigned finger, int status_fd, const struct fold_capture_monitor *monitor)
{
    RECGUID guid;
    if (!device || !identity || finger < 1 || finger > 10)
        return FOLD_VERIFY_ERROR;
    memcpy(&guid, identity, sizeof(guid));
    int fd = eventfd(0, EFD_CLOEXEC);
    if (fd < 0)
        return FOLD_VERIFY_ERROR;
    bool retry = false, match = false;
    tudor_async_res_t result = NULL;
    int outcome = -1;
    if (tudor_verify(device, guid, finger, &retry, &match, &result))
        outcome = wait_for_sample(result, fd, status_fd, monitor ? monitor->disconnect_fd : -1);
    close(fd);
    if (!outcome && retry)
        return FOLD_VERIFY_RETRY;
    if (outcome != 1)
        return FOLD_VERIFY_ERROR;
    return match ? FOLD_VERIFY_MATCH : FOLD_VERIFY_NO_MATCH;
}
