"""Build the Fold transaction worker from the pinned runtime and two OEM DLLs."""
import argparse
import hashlib
import os
import platform
from pathlib import Path
import re
import subprocess
import shutil
import shlex
import tempfile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vendor-protection"))
from prepare_protection import protection_sources


REV = "31dfdb06107fd1c35c9f9ceae72617e98eccc43a"
INSTALLER_SHA256 = "5f7c42cb5426079de9bebe0f24d3987d5d7edb0d0c4d7e8a6b01e33625e82773"
DLLS = {
    "synaFpAdapter153.dll": "75d711603934527e1cf886fa153f202991a7158e27c8d1bf02f81835c72f1182",
    "synaWudfBioHid153.dll": "4c9e969eb6c26c0447fc4fb80a5258d19d5ee7785f19e1d0ae6de35fd176fe68",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("package", type=Path, help="Lenovo N3LGF05W installer or directory with its two DLLs")
    parser.add_argument("-I", dest="includes", type=Path, action="append", default=[])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if platform.machine() != "x86_64":
        parser.error("The Fold DLLs require x86-64")
    checkout = args.checkout.resolve()
    revision = subprocess.check_output(["git", "-C", checkout, "rev-parse", "HEAD"], text=True).strip()
    if revision != REV:
        parser.error(f"Expected Popax21/synaTudor at {REV}")
    dirty = subprocess.check_output(
        ["git", "-C", checkout, "status", "--porcelain", "--", "libtudor"], text=True)
    if dirty:
        parser.error("The pinned libtudor source tree has local changes")
    source = checkout / "libtudor"
    with tempfile.TemporaryDirectory(prefix="x1fold-init-") as dirname:
        build = Path(dirname)
        (build / "libtudor").mkdir()
        package = args.package.resolve()
        if package.is_file():
            if hashlib.sha256(package.read_bytes()).hexdigest() != INSTALLER_SHA256:
                parser.error("Expected Lenovo n3lgf05w.exe")
            members = Path("code$GetExtractPath$") / "package"
            filters = []
            for name in DLLS:
                filters.extend(["--include", str(members / name)])
            subprocess.run(["innoextract", "--silent", *filters, str(package)], cwd=build, check=True)
            package = build / members
        objects = []
        for name, digest in DLLS.items():
            data = (package / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                parser.error(f"Unexpected Lenovo package file: {name}")
            (build / "libtudor" / name).write_bytes(data)
            obj = build / (name + ".o")
            subprocess.run(["ld", "-r", "-b", "binary", "-o", obj, "libtudor/" + name], cwd=build, check=True)
            objects.append(obj)
        # Use the vendor's actual module names and linker symbols.
        original = source / "src/tudor/driver.c"
        driver = build / "driver.c"
        driver.write_text(original.read_text().replace("synaFpAdapter104", "synaFpAdapter153")
                          .replace("synaWudfBioUsb104", "synaWudfBioHid153"))
        host = Path(__file__).resolve().parent
        listed = re.findall(r"'(src/[^']+\.c)'", (source / "meson.build").read_text())
        sources = [source / s for s in listed if source / s != original]
        sources[sources.index(original.with_name("device.c"))] = host / "fold_device.c"
        # Retain the real IOCTL bridge and biometric operations. The upstream
        # legacy USB open resets an entire composite device and its close
        # assumes storage contexts owned by a different adapter.
        device = original.with_name("device.c").read_bytes()
        if hashlib.sha256(device).hexdigest() != "73ce8f35fb67a4f6614415378c2666934626f52f86cc053b0a8521e0bb563315":
            parser.error("Unrecognized upstream WBF device implementation")
        source_text = device.decode()
        prefix = source_text[:source_text.index("bool tudor_open(")]
        biometrics = source_text[source_text.index("bool tudor_enroll_start("):]
        (build / "fold_wbf.inc").write_text(prefix + biometrics)
        sources = protection_sources(sources, source, build)
        compat = host.parent / "vendor-compat"
        winapi = source / "src/winapi"
        ecc_source = winapi / "bcrypt/ecc.c"
        ecc = build / "ecc.c"
        subprocess.run(["patch", "--batch", "--fuzz=0", "--output", ecc, ecc_source,
                        "--input", compat / "ecc-serialization.patch"], check=True)
        sources[sources.index(ecc_source)] = ecc
        registry = winapi / "wdf/reg.c"
        wdf_registry = build / "wdf_registry.c"
        subprocess.run(["patch", "--batch", "--fuzz=0", "--output", wdf_registry, registry,
                        "--input", compat / "wdf-registry-query.patch"], check=True)
        wdf_registry.write_text(wdf_registry.read_text().replace('#include "internal.h"',
                                                               '#include "winapi/wdf/internal.h"'))
        sources[sources.index(registry)] = wdf_registry
        sync = build / "sync.c"
        subprocess.run(["patch", "--batch", "--fuzz=0", "--output", sync, winapi / "sync.c",
                        "--input", compat / "event-deadline.patch"], check=True)
        sync.write_text(sync.read_text().replace('#include "internal.h"', '#include "winapi/internal.h"'))
        sources[sources.index(winapi / "sync.c")] = sync
        strings = build / "string.c"
        text = (winapi / "string.c").read_text().replace('#include "internal.h"', '#include "winapi/internal.h"')
        text = text.replace("return 1200; //UTF-16", "return 1252; //Windows ANSI code page")
        text = text.replace("case 65001:", "case 1252: case 65001:")
        strings.write_text(text.replace("WINAPI(WideCharToMultiByte)", "/* registered by fold_text.c */"))
        sources[sources.index(winapi / "string.c")] = strings
        wdf_source = winapi / "wdf/device.c"
        file_source = winapi / "wdf/file.c"
        wdf_file = build / "wdf_file.c"
        subprocess.run(["patch", "--batch", "--fuzz=0", "--output", wdf_file, file_source,
                        "--input", compat / "wdf-file-create.patch"], check=True)
        wdf_file.write_text(wdf_file.read_text().replace('#include "internal.h"', '#include "winapi/wdf/internal.h"'))
        sources[sources.index(file_source)] = wdf_file
        wdf = build / "wdf_callbacks.c"
        text = wdf_source.read_text().replace('#include "internal.h"', '#include "winapi/wdf/internal.h"')
        # Surface the guest's real attachment status to this single-device diagnostic.
        abort_on_attach = 'log_error("Error in WDF device attachment callbacks: 0x%x!", status);\n            abort();'
        if text.count(abort_on_attach) != 1:
            parser.error("Unrecognized upstream WDF attachment dispatcher")
        wdf.write_text(text.replace(abort_on_attach,
                       "extern void fold_attachment_failed(NTSTATUS);\n            fold_attachment_failed(status);"))
        sources[sources.index(wdf_source)] = wdf
        includes = [build, source / "inc", source / "src", original.parent, winapi / "crypt", *args.includes]
        flags = ["-I" + str(path.resolve()) for path in includes]
        native = host.parent / "libfprint"
        host_sources = [host / name for name in (
            "biometric_worker.c", "wdf_device.c", "fold_cm.c", "fold_text.c",
            "fold_module.c", "fold_station.c", "fold_message.c", "fold_store.c", "fold_registry.c")]
        host_sources += [compat / "fold_hid.c", compat / "fold_file.c", host / "capture_once.c",
                         native / "biometric-ipc.c", native / "transport.c"]
        pkgconf = os.environ.get("PKG_CONFIG", "pkg-config")
        def pkg_flags(option, *packages):
            return shlex.split(subprocess.check_output([pkgconf, option, *packages], text=True))
        flags += ["-Wl,--wrap=resolve_windows_api", "-DX1FOLD_SERVICE_WORKER",
                  *pkg_flags("--cflags", "gio-2.0", "libusb-1.0")]
        worker_libs = pkg_flags("--libs", "gio-2.0")
        exe = build / "check-init"
        cmd = ["gcc", "-std=gnu11", "-D_GNU_SOURCE", "-DDBGIMPORT", "-DDBGWDF", "-Wno-incompatible-pointer-types",
               *flags, *sources, driver, *host_sources, *objects,
               "-pthread", "-lm", *worker_libs, "-l:libcrypto.so.3",
               "-l:libusb-1.0.so.0", "-Wl,-z,noexecstack", "-o", exe]
        subprocess.run(cmd, cwd=build, check=True)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=args.output.parent, delete=False) as pending:
            pending_path = Path(pending.name)
        try:
            shutil.copy2(exe, pending_path)
            pending_path.replace(args.output)
        finally:
            pending_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
