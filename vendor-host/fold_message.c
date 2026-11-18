/* In-process USER32 thread messages for the headless vendor worker. */
#include "fold_message.h"
#include "winapi/internal.h"
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

_Static_assert(sizeof(struct fold_msg) == 48 &&
               offsetof(struct fold_msg, wparam) == 16 &&
               offsetof(struct fold_msg, time) == 32 &&
               offsetof(struct fold_msg, reserved) == 44, "Win64 MSG layout");

enum {
    WM_QUIT = 0x12, WM_TIMER = 0x113,
    WM_KEYDOWN = 0x100, WM_KEYUP = 0x101, WM_SYSKEYDOWN = 0x104, WM_SYSKEYUP = 0x105,
    ERROR_NOT_ENOUGH_MEMORY = 8, ERROR_NOT_SUPPORTED = 50, ERROR_INVALID_PARAMETER = 87,
    ERROR_INVALID_WINDOW_HANDLE = 1400, ERROR_INVALID_THREAD_ID = 1444,
    ERROR_NOT_ENOUGH_QUOTA = 1816, MAX_POSTED_MESSAGES = 10000
};

struct posted {
    struct fold_msg msg;
    struct posted *next;
};

struct message_queue {
    DWORD id;
    pthread_cond_t available;
    struct posted *first, *last;
    unsigned count;
    struct message_queue *next;
};

static struct message_queue *queues;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;
static pthread_key_t queue_key;
static int key_error;

static void destroy_queue(void *value)
{
    struct message_queue *queue = value;
    pthread_mutex_lock(&lock);
    struct message_queue **link = &queues;
    while (*link != queue) link = &(*link)->next;
    *link = queue->next;
    pthread_mutex_unlock(&lock);
    while (queue->first) {
        struct posted *msg = queue->first;
        queue->first = msg->next;
        free(msg);
    }
    pthread_cond_destroy(&queue->available);
    free(queue);
}

static void create_key(void)
{
    key_error = pthread_key_create(&queue_key, destroy_queue);
}

static struct message_queue *current_queue(void)
{
    pthread_once(&key_once, create_key);
    if (key_error) goto fail;
    struct message_queue *queue = pthread_getspecific(queue_key);
    if (queue) return queue;
    queue = calloc(1, sizeof(*queue));
    if (!queue) goto fail;
    if (pthread_cond_init(&queue->available, NULL)) goto free_queue;
    if (pthread_setspecific(queue_key, queue)) {
        pthread_cond_destroy(&queue->available);
        goto free_queue;
    }
    queue->id = win_get_thread_id();
    pthread_mutex_lock(&lock);
    queue->next = queues;
    queues = queue;
    pthread_mutex_unlock(&lock);
    return queue;

free_queue:
    free(queue);
fail:
    winerr_set_code(ERROR_NOT_ENOUGH_MEMORY);
    return NULL;
}

bool fold_message_init(void)
{
    return current_queue() != NULL;
}

static BOOL __winfnc PostThreadMessageW(DWORD id, UINT message, ULONG_PTR wparam, LONG_PTR lparam)
{
    if (!current_queue()) return FALSE;
    pthread_mutex_lock(&lock);
    struct message_queue *queue = queues;
    while (queue && queue->id != id) queue = queue->next;
    int error = 0;
    if (!queue) {
        error = ERROR_INVALID_THREAD_ID;
    } else if (queue->count >= MAX_POSTED_MESSAGES) {
        error = ERROR_NOT_ENOUGH_QUOTA;
    } else {
        struct posted *item = calloc(1, sizeof(*item));
        if (!item) {
            error = ERROR_NOT_ENOUGH_MEMORY;
        } else {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            item->msg.time = (DWORD)((uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000);
            item->msg.message = message;
            item->msg.wparam = wparam;
            item->msg.lparam = lparam;
            if (queue->last) queue->last->next = item;
            else queue->first = item;
            queue->last = item;
            ++queue->count;
            pthread_cond_signal(&queue->available);
        }
    }
    pthread_mutex_unlock(&lock);
    if (error) winerr_set_code(error);
    return !error;
}
WINAPI(PostThreadMessageW)

static bool take_message(struct message_queue *queue, struct fold_msg *out, UINT min, UINT max)
{
    struct posted *prev = NULL;
    for (struct posted *item = queue->first; item; prev = item, item = item->next) {
        UINT id = item->msg.message;
        if ((min || max) && id != WM_QUIT && (id < min || id > max)) continue;
        *out = item->msg;
        if (prev) prev->next = item->next;
        else queue->first = item->next;
        if (queue->last == item) queue->last = prev;
        --queue->count;
        free(item);
        return true;
    }
    return false;
}

static void unlock_queue(void *mutex)
{
    pthread_mutex_unlock(mutex);
}

static int __winfnc GetMessageW(struct fold_msg *out, HANDLE hwnd, UINT min, UINT max)
{
    struct message_queue *queue = current_queue();
    if (!queue) return -1;
    if (hwnd && hwnd != INVALID_HANDLE_VALUE) {
        winerr_set_code(ERROR_INVALID_WINDOW_HANDLE);
        return -1;
    }
    if (!out || (min | max) > 0xffff) {
        winerr_set_code(ERROR_INVALID_PARAMETER);
        return -1;
    }
    int wait_error = 0;
    pthread_mutex_lock(&lock);
    /* Cancellation of a blocking receiver must unlock before its TLS destructor runs. */
    pthread_cleanup_push(unlock_queue, &lock);
    while (!take_message(queue, out, min, max)) {
        wait_error = pthread_cond_wait(&queue->available, &lock);
        if (wait_error) break;
    }
    pthread_cleanup_pop(1);
    if (wait_error) {
        winerr_set_code(ERROR_INVALID_PARAMETER);
        return -1;
    }
    return out->message != WM_QUIT;
}
WINAPI(GetMessageW)

static BOOL __winfnc TranslateMessage(const struct fold_msg *msg)
{
    if (!current_queue()) return FALSE;
    if (!msg) winerr_set_code(ERROR_INVALID_PARAMETER);
    else if (msg->hwnd) winerr_set_code(ERROR_INVALID_WINDOW_HANDLE);
    else if (msg->message == WM_KEYDOWN || msg->message == WM_KEYUP ||
             msg->message == WM_SYSKEYDOWN || msg->message == WM_SYSKEYUP)
        winerr_set_code(ERROR_NOT_SUPPORTED);
    return FALSE; /* No keyboard input or character translation in this process. */
}
WINAPI(TranslateMessage)

static LONG_PTR __winfnc DispatchMessageW(const struct fold_msg *msg)
{
    if (!current_queue()) return 0;
    if (!msg) winerr_set_code(ERROR_INVALID_PARAMETER);
    else if (msg->hwnd) winerr_set_code(ERROR_INVALID_WINDOW_HANDLE);
    else if (msg->message == WM_TIMER && msg->lparam) winerr_set_code(ERROR_NOT_SUPPORTED);
    return 0; /* A thread message has no destination window procedure. */
}
WINAPI(DispatchMessageW)
