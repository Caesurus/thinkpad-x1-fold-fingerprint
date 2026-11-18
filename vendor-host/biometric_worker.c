/* One authenticated fprintd operation per process. The private channel and
 * verified HID fd arrive together from the root-managed activation socket. */
#include "tudor/internal.h"
#include "fold_cm.h"
#include "fold_device.h"
#include "fold_store.h"
#include "capture_once.h"
#include "../vendor-compat/fold_file.h"
#include "../vendor-protection/protection.h"
#include "../libfprint/biometric-ipc.h"
#include <fcntl.h>
#include <linux/hidraw.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

extern int x1fold_read_serial(int fd, unsigned char serial[6], void *cancellable, void *error);

struct transaction {
    struct fold_bio_frame frame;
    int channel;
};

static bool reply(struct transaction *t, enum fold_bio_event event, unsigned stage)
{
    struct fold_bio_frame frame = t->frame;
    frame.event = event;
    frame.stage = stage;
    return send(t->channel, &frame, sizeof(frame), MSG_NOSIGNAL) == sizeof(frame);
}

static bool progress(void *data, unsigned stage, bool retry)
{
    return reply(data, retry ? FOLD_RETRY : FOLD_PROGRESS, retry ? 0 : stage);
}

static bool bind_sensor(int fd, const uint8_t serial[6])
{
    struct stat st;
    if (!fold_cm_bind(fd) || fstat(fd, &st)) return false;
    char path[128];
    snprintf(path, sizeof(path), "/sys/dev/char/%u:%u/device/../../bcdDevice",
             major(st.st_rdev), minor(st.st_rdev));
    FILE *attribute = fopen(path, "r");
    if (!attribute) return false;
    unsigned revision;
    bool ok = fscanf(attribute, "%x", &revision) == 1 && revision <= UINT16_MAX;
    fclose(attribute);
    unsigned char live[6];
    int flags = fcntl(fd, F_GETFL);
    return ok && flags >= 0 && !fcntl(fd, F_SETFL, flags | O_NONBLOCK) &&
           x1fold_read_serial(fd, live, NULL, NULL) && !memcmp(live, serial, sizeof(live)) &&
           fold_file_bind(fd, revision);
}

static bool authenticated(int fd)
{
    unsigned char report[20] = {0x11};
    uint32_t length = 0;
    if (ioctl(fd, HIDIOCGFEATURE(sizeof(report)), report) != sizeof(report) ||
        memcmp(report + 1, "synaptic", 8)) return false;
    memcpy(&length, report + 9, sizeof(length));
    return length > 0 && length <= 7 && report[13] != 0;
}

static enum fold_bio_event transact(struct transaction *tx, struct tudor_device *device)
{
    const struct fold_bio_identity *id = &tx->frame.print;
    struct fold_capture_monitor monitor = {.disconnect_fd = tx->channel, .report = progress, .data = tx};
    switch (tx->frame.op) {
    case FOLD_ENROLL:
        if (fold_device_record_count(device, id->guid, id->finger) != 0 ||
            !fold_enroll_monitored(device, id->guid, id->finger, -1, &monitor))
            return FOLD_ERROR;
        return fold_device_record_count(device, id->guid, id->finger) == 1 ? FOLD_ENROLLED : FOLD_ERROR;
    case FOLD_VERIFY:
        if (fold_device_record_count(device, id->guid, id->finger) != 1) return FOLD_ERROR;
        switch (fold_verify_monitored(device, id->guid, id->finger, -1, &monitor)) {
        case FOLD_VERIFY_MATCH: return FOLD_MATCH;
        case FOLD_VERIFY_NO_MATCH: return FOLD_NO_MATCH;
        case FOLD_VERIFY_RETRY: return FOLD_RETRY;
        default: return FOLD_ERROR;
        }
    case FOLD_DELETE:
        return fold_device_delete_print(device, id->guid, id->finger) ? FOLD_DELETED : FOLD_ERROR;
    default:
        return FOLD_ERROR;
    }
}

int main(void)
{
    int hid = -1;
    struct transaction tx;
    if (!geteuid() || fold_bio_accept(STDIN_FILENO, &tx.frame, &tx.channel, &hid)) return 1;
    /* The SDK may print payloads to stdout or stderr. Journal only the explicit
     * startup stage and final event for this transaction. */
    int status = fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 3);
    int sink = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (sink < 0 || dup2(sink, STDOUT_FILENO) < 0 || dup2(sink, STDERR_FILENO) < 0) return 1;
    close(sink);
    enum fold_bio_event result = FOLD_ERROR;
    const char *state = secure_getenv("STATE_DIRECTORY");
    int dir = state ? open(state, O_RDONLY | O_DIRECTORY | O_CLOEXEC) : -1;
    struct fold_store store = {.lock = -1, .directory = -1};
    if (dir < 0 || fold_protection_start_systemd() ||
        !fold_store_open(&store, dir, tx.frame.print.serial) ||
        !bind_sensor(hid, tx.frame.print.serial) || !tudor_init()) goto done;
    struct fold_open_result opened;
    struct fold_device *session = fold_device_open(&store, &opened);
    dprintf(status, "Fold reader open %s, status 0x%08x\n", opened.stage, opened.code);
    if (!session) goto done;
    if (authenticated(hid))
        result = transact(&tx, fold_device_ready(session));
    bool closed = fold_device_close(session);
    if (!closed && result != FOLD_ENROLLED && result != FOLD_DELETED) result = FOLD_ERROR;
done:
    fold_file_unbind();
    fold_store_close(&store);
    if (dir >= 0) close(dir);
    close(hid);
    bool sent = reply(&tx, result, 0);
    dprintf(status, "Fold transaction %u finished with event %u, delivered %u\n", tx.frame.op, result, sent);
    close(tx.channel);
    return !sent || result == FOLD_ERROR;
}
