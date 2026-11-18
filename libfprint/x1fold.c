// SPDX-License-Identifier: LGPL-2.1-or-later
#include <fpi-device.h>
#include <gmodule.h>
#include <glib-unix.h>
#include <errno.h>
#include <gudev/gudev.h>
#include <unistd.h>

#include "transport.h"
#include "print-identity.h"

typedef struct {
  FpDevice parent;
  gchar *hidraw;
  dev_t devnum;
  guint8 serial[6];
  gboolean identified;
  int fd;
  struct fold_bio_session session;
  GSource *events, *deadline;
} FpiDeviceX1Fold;

typedef FpDeviceClass FpiDeviceX1FoldClass;
G_DEFINE_TYPE (FpiDeviceX1Fold, fpi_device_x1fold, FP_TYPE_DEVICE)

static const FpIdEntry ids[] = {
  { .udev_types = FPI_DEVICE_UDEV_SUBTYPE_HIDRAW, .hid_id = { .vid = 0x17ef, .pid = 0x6142 } },
  { .udev_types = 0 }
};

static void read_identity (FpDevice *device, GAsyncReadyCallback done);
static void probe_done (GObject *source, GAsyncResult *result, gpointer data);

static void
probe (FpDevice *device)
{
  FpiDeviceX1Fold *self = (FpiDeviceX1Fold *) device;
  const gchar *seed = fpi_device_get_udev_data (device, FPI_DEVICE_UDEV_SUBTYPE_HIDRAW);
  g_autoptr(GUdevClient) client = g_udev_client_new (NULL);
  g_autoptr(GUdevDevice) raw = g_udev_client_query_by_device_file (client, seed);
  g_autoptr(GUdevDevice) keyboard = raw ? g_udev_device_get_parent_with_subsystem (raw, "usb", "usb_device") : NULL;
  g_autolist(GUdevDevice) siblings = NULL;

  if (keyboard &&
      g_strcmp0 (g_udev_device_get_sysfs_attr (keyboard, "idVendor"), "17ef") == 0 &&
      g_strcmp0 (g_udev_device_get_sysfs_attr (keyboard, "idProduct"), "6142") == 0)
    siblings = g_udev_client_query_by_subsystem (client, "hidraw");

  /* libfprint supplies the first hidraw with this VID/PID, which can be
   * a keyboard collection. Scope the search to that exact USB device. */
  for (GList *item = siblings; item; item = item->next)
    {
      GUdevDevice *candidate = item->data;
      g_autoptr(GUdevDevice) parent = g_udev_device_get_parent_with_subsystem (candidate, "usb", "usb_device");
      if (!parent || g_strcmp0 (g_udev_device_get_sysfs_path (parent),
                               g_udev_device_get_sysfs_path (keyboard)) != 0)
        continue;

      g_autoptr(GUdevDevice) iface = g_udev_device_get_parent_with_subsystem (candidate, "usb", "usb_interface");
      if (!iface || g_strcmp0 (g_udev_device_get_sysfs_attr (iface, "bInterfaceNumber"), "04") != 0)
        continue;

      g_autoptr(GUdevDevice) hid = g_udev_device_get_parent_with_subsystem (candidate, "hid", NULL);
      if (!hid || !g_udev_device_get_device_file (candidate))
        continue;

      g_autofree gchar *path = g_build_filename (g_udev_device_get_sysfs_path (hid), "report_descriptor", NULL);
      g_autofree gchar *descriptor = NULL;
      gsize size;
      if (!g_file_get_contents (path, &descriptor, &size, NULL) ||
          !x1fold_is_descriptor ((const guint8 *) descriptor, size))
        continue;

      if (self->hidraw)
        {
          /* Ambiguous interface layout. Do not guess a node. */
          g_clear_pointer (&self->hidraw, g_free);
          break;
        }
      self->hidraw = g_strdup (g_udev_device_get_device_file (candidate));
      self->devnum = g_udev_device_get_device_number (candidate);
    }

  if (!self->hidraw)
    {
      fpi_device_probe_complete (device, NULL, NULL, fpi_device_error_new_msg (
          FP_DEVICE_ERROR_NOT_SUPPORTED, "Fingerprint HID interface 04 missing or ambiguous"));
      return;
    }
  if (g_strcmp0 (g_getenv ("X1FOLD_PASSIVE_DISCOVERY"), "1") == 0)
    fpi_device_probe_complete (device, X1FOLD_UNIDENTIFIED, NULL, NULL);
  else
    read_identity (device, probe_done);
}

static void
open_worker (GTask *task, gpointer source, gpointer data, GCancellable *cancellable)
{
  FpiDeviceX1Fold *self = source;
  g_autoptr(GError) error = NULL;
  int fd = x1fold_open_sensor (self->hidraw, self->devnum, data, cancellable, &error);
  if (fd < 0)
    g_task_return_error (task, g_steal_pointer (&error));
  else
    g_task_return_int (task, fd);
}

static void
probe_done (GObject *source, GAsyncResult *result, gpointer data)
{
  FpiDeviceX1Fold *self = (FpiDeviceX1Fold *) source;
  g_autoptr(GError) error = NULL;
  int fd = g_task_propagate_int (G_TASK (result), &error);
  if (fd < 0)
    {
      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED))
        fpi_device_probe_complete (FP_DEVICE (self), X1FOLD_UNIDENTIFIED, NULL, NULL);
      else
        fpi_device_probe_complete (FP_DEVICE (self), NULL, NULL, g_steal_pointer (&error));
      return;
    }
  close (fd);
  memcpy (self->serial, g_task_get_task_data (G_TASK (result)), sizeof self->serial);
  g_autofree gchar *id = x1fold_sensor_id (self->serial);
  self->identified = id != NULL;
  fpi_device_probe_complete (FP_DEVICE (self), id ? id : X1FOLD_UNIDENTIFIED, NULL, NULL);
}

static void
open_done (GObject *source, GAsyncResult *result, gpointer data)
{
  FpiDeviceX1Fold *self = (FpiDeviceX1Fold *) source;
  g_autoptr(GError) error = NULL;
  self->fd = g_task_propagate_int (G_TASK (result), &error);
  if (self->fd >= 0 && self->identified &&
      memcmp (self->serial, g_task_get_task_data (G_TASK (result)), sizeof self->serial) != 0)
    {
      close (self->fd);
      self->fd = -1;
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_REMOVED, "Fingerprint sensor changed since discovery");
    }
  fpi_device_open_complete (FP_DEVICE (self), g_steal_pointer (&error));
}

static void
read_identity (FpDevice *device, GAsyncReadyCallback done)
{
  g_autoptr(GTask) task = g_task_new (device, fpi_device_get_cancellable (device), done, NULL);
  g_task_set_task_data (task, g_malloc0 (6), g_free);
  /* The worker owns cancellation and transfers an open fd on success. */
  g_task_set_check_cancellable (task, FALSE);
  g_task_run_in_thread (task, open_worker);
}

static void
open_device (FpDevice *device)
{
  read_identity (device, open_done);
}

static void
close_device (FpDevice *device)
{
  FpiDeviceX1Fold *self = (FpiDeviceX1Fold *) device;
  close (self->fd);
  self->fd = -1;
  fpi_device_close_complete (device, NULL);
}

static void
clear_transaction (FpiDeviceX1Fold *self)
{
  if (self->events)
    {
      g_source_destroy (self->events);
      g_clear_pointer (&self->events, g_source_unref);
    }
  if (self->deadline)
    {
      g_source_destroy (self->deadline);
      g_clear_pointer (&self->deadline, g_source_unref);
    }
  fold_bio_close (&self->session);
}

static void
transaction_failed (FpDevice *device, GError *error)
{
  clear_transaction ((FpiDeviceX1Fold *) device);
  fpi_device_action_error (device, error);
}

static gboolean
transaction_timeout (gpointer data)
{
  transaction_failed (data, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                                                  "Fingerprint operation timed out"));
  return G_SOURCE_REMOVE;
}

static gboolean
transaction_event (gint fd, GIOCondition condition, gpointer data)
{
  FpDevice *device = FP_DEVICE (data);
  FpiDeviceX1Fold *self = (FpiDeviceX1Fold *) device;
  struct fold_bio_session *session = &self->session;
  enum fold_bio_event event;
  if (fold_bio_next (session, -1, &event) < 0)
    {
      transaction_failed (device, g_error_new (G_IO_ERROR, g_io_error_from_errno (errno),
                                                "Fingerprint worker: %s", g_strerror (errno)));
      return G_SOURCE_REMOVE;
    }
  if (event == FOLD_PROGRESS || (event == FOLD_RETRY && session->request.op == FOLD_ENROLL))
    {
      GError *retry = event == FOLD_RETRY ? fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL) : NULL;
      fpi_device_enroll_progress (device, MIN (session->stage, 10), NULL, retry);
      return G_SOURCE_CONTINUE;
    }

  clear_transaction (self);
  if (event == FOLD_DUPLICATE)
    fpi_device_enroll_complete (device, NULL, fpi_device_error_new (FP_DEVICE_ERROR_DATA_DUPLICATE));
  else if (event == FOLD_ENROLLED)
    {
      FpPrint *print;
      GError *error = NULL;
      fpi_device_get_enroll_data (device, &print);
      if (!x1fold_save_print_identity (device, print, &session->request.print, &error))
        fpi_device_enroll_complete (device, NULL, error);
      else
        {
          fpi_print_set_device_stored (print, TRUE);
          fpi_device_enroll_complete (device, g_object_ref (print), NULL);
        }
    }
  else if (event == FOLD_DELETED)
    fpi_device_delete_complete (device, NULL);
  else
    {
      if (event == FOLD_RETRY)
        fpi_device_verify_report (device, FPI_MATCH_ERROR, NULL, fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
      else
        fpi_device_verify_report (device, event == FOLD_MATCH ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL, NULL, NULL);
      fpi_device_verify_complete (device, NULL);
    }
  return G_SOURCE_REMOVE;
}

static void
start_transaction (FpDevice *device, enum fold_bio_operation op)
{
  FpiDeviceX1Fold *self = (FpiDeviceX1Fold *) device;
  struct fold_bio_identity identity = {0};
  FpPrint *print;
  GError *error = NULL;
  if (op == FOLD_ENROLL)
    {
      fpi_device_get_enroll_data (device, &print);
      identity.finger = x1fold_winbio_finger (fp_print_get_finger (print));
      memcpy (identity.serial, self->serial, sizeof identity.serial);
      if (!self->identified || !identity.finger || fold_bio_new_guid (identity.guid))
        error = fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID);
    }
  else
    {
      if (op == FOLD_VERIFY)
        fpi_device_get_verify_data (device, &print);
      else
        fpi_device_get_delete_data (device, &print);
      x1fold_load_print_identity (device, print, &identity, &error);
    }
  if (!error && fold_bio_start (&self->session, op, &identity, self->fd, -1) < 0)
    {
      if (errno == ENOENT)
        error = fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED, "Fold fingerprint worker unavailable");
      else
        error = g_error_new (G_IO_ERROR, g_io_error_from_errno (errno),
                             "Could not start fingerprint worker: %s", g_strerror (errno));
    }
  if (error)
    {
      transaction_failed (device, error);
      return;
    }

  GMainContext *context = g_main_context_get_thread_default ();
  self->events = g_unix_fd_source_new (self->session.socket, G_IO_IN | G_IO_HUP | G_IO_ERR);
  g_source_set_callback (self->events, G_SOURCE_FUNC (transaction_event), device, NULL);
  g_source_attach (self->events, context);
  self->deadline = g_timeout_source_new (op == FOLD_ENROLL ? 120000 : 30000);
  g_source_set_callback (self->deadline, transaction_timeout, device, NULL);
  g_source_attach (self->deadline, context);
}

static void enroll (FpDevice *device) { start_transaction (device, FOLD_ENROLL); }
static void verify (FpDevice *device) { start_transaction (device, FOLD_VERIFY); }
static void delete_print (FpDevice *device) { start_transaction (device, FOLD_DELETE); }

static void
cancel_transaction (FpDevice *device)
{
  FpiDeviceX1Fold *self = (FpiDeviceX1Fold *) device;
  if (self->events)
    transaction_failed (device, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                                       "Fingerprint operation cancelled"));
}

static void
finalize (GObject *object)
{
  FpiDeviceX1Fold *self = (FpiDeviceX1Fold *) object;
  if (self->fd >= 0)
    close (self->fd);
  g_free (self->hidraw);
  G_OBJECT_CLASS (fpi_device_x1fold_parent_class)->finalize (object);
}

static void
fpi_device_x1fold_class_init (FpiDeviceX1FoldClass *cls)
{
  G_OBJECT_CLASS (cls)->finalize = finalize;
  cls->id = "x1fold_hid";
  cls->full_name = "ThinkPad X1 Fold keyboard fingerprint reader";
  cls->type = FP_DEVICE_TYPE_UDEV;
  cls->id_table = ids;
  cls->scan_type = FP_SCAN_TYPE_PRESS;
  cls->probe = probe;
  cls->open = open_device;
  cls->close = close_device;
  cls->enroll = enroll;
  cls->verify = verify;
  cls->delete = delete_print;
  cls->cancel = cancel_transaction;
  cls->nr_enroll_stages = 10;
  cls->temp_hot_seconds = -1;
  fpi_device_class_auto_initialize_features (cls);
  /* fprintd gates per-print deletion on persistent storage. This reader
   * supports deleting a known identity independently of listing or clearing. */
  cls->features |= FP_DEVICE_FEATURE_STORAGE;
}

static void
fpi_device_x1fold_init (FpiDeviceX1Fold *self)
{
  self->fd = -1;
  self->session.socket = -1;
}

G_MODULE_EXPORT GType
fpi_tod_shared_driver_get_type (void)
{
  return fpi_device_x1fold_get_type ();
}
