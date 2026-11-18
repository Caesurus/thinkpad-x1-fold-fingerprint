"""Replace the DPAPI and CryptoAPI key import functions in the pinned build."""
from pathlib import Path
import hashlib

CRYPT_SHA256 = "0f650c960ee1e7b3daceac0258e7e8321daf57432d855cb40d5dae257d77244b"


def protection_sources(sources, libtudor, build):
    original = libtudor / "src/winapi/crypt/crypt.c"
    content = original.read_bytes()
    if hashlib.sha256(content).hexdigest() != CRYPT_SHA256:
        raise ValueError("Unrecognized relink crypt.c; refusing to build with unsafe protection functions")
    begin = content.index(b"__winfnc BOOL CryptProtectData(")
    end = content.index(b"__winfnc BOOL CryptGenRandom(", begin)
    import_begin = content.index(b"__winfnc BOOL CryptImportKey(")
    import_end = content.index(b"__winfnc BOOL CryptCreateHash(", import_begin)
    trimmed = build / "crypt_without_dpapi.c"
    trimmed.write_bytes(content[:import_begin] + content[import_end:begin] + content[end:])
    result = list(sources)
    result[result.index(original)] = trimmed
    result.append(Path(__file__).resolve().with_name("protection.c"))
    result.append(Path(__file__).resolve().with_name("key_import.c"))
    result.append(Path(__file__).resolve().with_name("hash_provider.c"))
    return result
