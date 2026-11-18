#ifndef X1FOLD_CAPTURE_ONCE_H
#define X1FOLD_CAPTURE_ONCE_H

#include <stdbool.h>
#include <stdint.h>
struct tudor_device;

/* Single-process diagnostic. The supervisor must also bound guest calls. */
bool fold_capture_once(struct tudor_device *device, int status_fd);

struct fold_capture_monitor {
    int disconnect_fd;
    bool (*report)(void *data, unsigned stage, bool retry);
    void *data;
};
bool fold_enroll_monitored(struct tudor_device *, const uint8_t identity[16], unsigned finger,
                           int status_fd, const struct fold_capture_monitor *);
bool fold_enroll_print(struct tudor_device *device, const uint8_t identity[16],
                       unsigned finger, int status_fd);
enum fold_verdict { FOLD_VERIFY_ERROR, FOLD_VERIFY_RETRY, FOLD_VERIFY_NO_MATCH, FOLD_VERIFY_MATCH };
enum fold_verdict fold_verify_print(struct tudor_device *device, const uint8_t identity[16],
                                    unsigned finger, int status_fd);

enum fold_verdict fold_verify_monitored(struct tudor_device *, const uint8_t identity[16], unsigned finger,
                                        int status_fd, const struct fold_capture_monitor *);

#endif
