#ifndef X1FOLD_MESSAGE_H
#define X1FOLD_MESSAGE_H

#include "winapi/windows.h"

/* Win64 MSG. Coordinates are always zero in the headless host. */
struct fold_msg {
    HANDLE hwnd;
    UINT message;
    ULONG_PTR wparam;
    LONG_PTR lparam;
    DWORD time;
    LONG x, y;
    DWORD reserved;
};

bool fold_message_init(void);

#endif
