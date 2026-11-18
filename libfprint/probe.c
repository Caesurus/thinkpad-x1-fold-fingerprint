// SPDX-License-Identifier: LGPL-2.1-or-later
#include <fprint.h>
#include <stdio.h>

int
main (int argc, char **argv)
{
  gboolean open_sensor = argc == 2 && g_str_equal (argv[1], "--open");
  if (argc > 1 && !open_sensor)
    {
      g_printerr ("Usage: %s [--open]\n", argv[0]);
      return 2;
    }

  if (!open_sensor)
    g_setenv ("X1FOLD_PASSIVE_DISCOVERY", "1", TRUE);
  g_autoptr(FpContext) context = fp_context_new ();
  GPtrArray *devices = fp_context_get_devices (context);
  for (guint i = 0; i < devices->len; i++)
    {
      FpDevice *device = g_ptr_array_index (devices, i);
      if (!g_str_equal (fp_device_get_driver (device), "x1fold_hid"))
        continue;
      g_print ("Discovered %s (%s)\n", fp_device_get_name (device), fp_device_get_driver (device));
      if (open_sensor)
        {
          g_autoptr(GError) error = NULL;
          if (!fp_device_open_sync (device, NULL, &error) ||
              !fp_device_close_sync (device, NULL, &error))
            {
              g_printerr ("%s\n", error->message);
              return 1;
            }
          g_print ("The sensor answered GET_VERSION. Closed the device.\n");
        }
      return 0;
    }
  g_printerr ("No X1 Fold fingerprint HID found by libfprint\n");
  return 1;
}
