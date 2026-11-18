# Native Fold fingerprint backend

The target is the USB-connected ThinkPad X1 Fold 16 Gen 1 keyboard, USB `17ef:6142`, vendor HID interface 04. The reference driver is Lenovo N3LGF05W, with `synaFpAdapter153.dll` and `synaWudfBioHid153.dll`. The keyboard presents its own HID transport. Other Synaptics USB readers can use different transport and pairing policies.

## Build the native components

```sh
make native native-inspect
make check
```

`make native` produces `build/libx1fold-native.a`. It needs Linux HID headers, GLib/GIO development files, OpenSSL 3 headers and a C toolchain. Consumers using certificate verification link libcrypto. The native diagnostic accepts an inherited reader descriptor and reports public firmware metadata when the session is idle. The native targets build offline with both Windows inputs absent. The default build and installer still use the original worker for biometric operations.

| Operation | Native branch | Evidence and outstanding work |
| --- | --- | --- |
| Device identity, firmware metadata, session status | Implemented in C | The TOD entry point uses the same transport to read the serial. Mock tests exercise the actual plugin and active, idle and malformed HID feature replies. |
| Long commands and replies | Implemented in C | Packet-socket tests exercise report and fragment boundaries, event interleaving, cancellation, timeout and oversize responses. Synchronous metadata operations skip events. A capture worker will need to consume them. |
| Verify the sensor certificate | Implemented for the advanced-security product 0x41, firmware 10.1 profile | Verifies the ECDSA/SHA-256 issuer signature and validates the P-256 subject point. Passed on a published certificate from a related 06cb:00ff reader. The Fold certificate and proof of the live peer remain unverified by this code. |
| Reuse an existing pairing | OEM worker only | A fresh OEM worker previously read HOST and opened an authenticated session with writes, formatting and new pairing disabled. The format and authorized use of the host credential still need to be established for the native worker. |
| Fresh pairing, ownership and key changes | OEM worker only | The OEM path obtained an accepted pairing. A Linux-native issuance path for a host certificate has yet to be established. The host certificate issuer and the sensor certificate issuer have different roles. |
| Secure session and authenticated commands | OEM worker only | Implement the handshake using the paired host identity, validate the peer and Finished messages, and handle close, cancellation and reconnect. A session-status bit reports device state and supplies no proof of peer identity. |
| Capture, enrollment and verification | OEM worker only | Trace the encrypted device commands, finger events, sample acceptance, multi-touch commit and operation-scoped match results. Require a real right-index match and a rejection with a different finger. |
| Record query and individual deletion | OEM worker only | Map per-record operations to the existing sensor, GUID and finger binding. Verify deletion using a separate test enrollment. |
| Firmware, configuration, diagnostics | Public firmware query only | The Fold DLL carries a signed main firmware update older than the measured build 3654703. Package applicability, update and recovery are separate from the authentication path. No native update was attempted. |

## DLL call paths

RVAs below refer to the Fold v153 PE images. The package and file SHA-256 values are recorded in the repository's worker builder. Names for internal HID functions come from diagnostic string references matched to PE function bounds. Windows device-control numbers identify requests between the two DLLs. The on-wire HID commands are a separate protocol.

| Image | Entry or path | Evidence |
| --- | --- | --- |
| Adapter | `WbioQueryEngineInterface` 0x5980, `WbioQuerySensorInterface` 0xa2f0, `WbioQueryStorageInterface` 0xe5f0 | Return interface tables at 0x29020, 0x29190 and 0x292b0 respectively. |
| Adapter | StartCapture 0x6990, FinishCapture 0x6f50, PushDataToEngine 0x7500 | StartCapture submits Windows device control 0x440014. |
| Adapter | AcceptSampleData 0x25c0, VerifyFeatureSet 0x28d0, IdentifyFeatureSet 0x2b10 | VerifyFeatureSet calls helper 0x1150, which requests device control 0x442058 with input length 0x1088 and output capacity 0x18ac. This establishes where to follow a verification request. It does not establish the match algorithm or response field. |
| Adapter | UpdateEnrollment 0x30d0, CheckForDuplicate 0x3820, CommitEnrollment 0x3b20 | Distinct engine callbacks for updating, checking and committing the enrollment. |
| Adapter | DeleteRecord 0xbc60, QueryBySubject 0xc1e0, GetRecordCount 0xc6d0 | Storage callbacks used to address and manage records. |
| HID | `tudorTlsSessionStart` 0x8b7f0 | Direct calls include pairing-presence check 0x8fe80, HOST pairing lookup 0x8d6b0, host and sensor session-status queries 0x8c8d0 and 0x8c6b0, context initialization 0x8d090 and establishment 0x96470. Branches depend on current state. |
| HID | `tudorTlsInitCtx` 0x8d090 | Calls public-key selection 0x95680, pairing-data retrieval 0x8fbd0 and TLS initialization 0x95940. Wrap and unwrap routines are at 0x96f80 and 0x97240. |
| HID | Capture start/process/finish at 0x7ba50, 0x7be70 and 0x7c760 | The DLL also contains `misIdentifyMatchCmd` at 0xa48f0. Its name alone cannot establish that the Fold uses it for one-to-one verification. |

### Verification across the Windows driver boundary

The adapter and HID DLL meet at Windows device control `0x442058`. In the HID dispatcher, the conditional at 0x814f selects the handler at 0x158e4. The handler invokes vtable slot 0x70. For the `CEisMisEIV` implementation, the vtable at 0xc9530 resolves that slot to 0x10f10, which invokes slot 0x110. That target is `CEisMisEIV::AuthenticateUserStorageOnSensor` at 0x10f40. Its direct call graph reaches `vfmUtilAuthPrep`, `vfmUtilAuthGetUpdatedTemplate` and `vfmUtilAuthUnPrep`. This ties the WinBio callback to a specific sensor-storage implementation. A hardware trace still needs to confirm the selected implementation and identify the authenticated response that supplies the verdict.

The same HID vtable contains enrollment create (0x11d20), update (0x120b0), commit (0x11800), discard (0x11f90) and duplicate check (0x116e0). Capture and enrollment are separate state machines. Receiving an image or an accepted enrollment sample does not establish a successful identity check.

## Certificate check

The 400-byte sensor certificate carries its P-256 coordinates as two 68-byte little-endian integers. The first 142 bytes are signed, followed by a little-endian DER signature length and a signature field. The Fold DLL contains both firmware-10.1 public issuer points. For the tested profile, security bit 13 selects the issuer. The test case on related hardware used the selected key, rejected the other key and rejected changes to signed data and signature. Production code returns the validated public key only. The handshake must still authenticate a fresh session.

For an independent repeat, take the 400-byte sensor certificate from the public pairing response in frames 244 and 246 of `finger2.pcapng` (Linux USB capture header length 64 per frame). Concatenate the USB payloads, check for 802 bytes and zero status, and take bytes 402 through 801 inclusive. Run `build/test-certificate /path/to/public-sensor-certificate.bin` after `make check`. The normal build needs neither a packet capture nor a third-party source checkout. [Published USB recording](https://github.com/vojtapl/synaTudorMiS/tree/5b3aecb3432b67083beeabdc1cfb0718513a83dd/reverse%20engineering/SP141455/Wireshark%20usb%20log)

## Hardware acceptance

The next milestone is a native cold reconnect with an authorized host credential, an authenticated firmware or status request, and a clean disconnect. Then exercise separate enrollment, correct-finger verification, wrong-finger rejection, targeted deletion and cancellation through fprintd. Test a second operation immediately after the first, followed by USB reconnect. Only a physical match and rejection using the native worker can establish parity for desktop unlock.
