# Native Fold fingerprint backend

The target is the USB-connected ThinkPad X1 Fold 16 Gen 1 keyboard, USB `17ef:6142`, vendor HID interface 04. The reference driver is Lenovo N3LGF05W, with `synaFpAdapter153.dll` and `synaWudfBioHid153.dll`. The keyboard presents its own HID transport. Other Synaptics USB readers can use different transport and pairing policies.

## Build the native components

```sh
make native native-inspect
make check
```

`make native` produces `build/libx1fold-native.a`. It needs Linux HID headers, GLib/GIO development files, OpenSSL 3 headers and a C toolchain. Consumers using certificates or encrypted sessions link libcrypto. The session integration tests use Python cryptography as an independent peer. The native diagnostic accepts an inherited reader descriptor and reports public firmware metadata when the session is idle. The native targets build offline with both Windows inputs absent. The default build and installer still use the original worker for biometric operations.

| Operation | Native branch | Evidence and outstanding work |
| --- | --- | --- |
| Device identity, firmware metadata, session status | Implemented in C | The TOD entry point uses the same transport to read the serial. Mock tests exercise the actual plugin and active, idle and malformed HID feature replies. |
| Long commands and replies | Implemented in C | Packet-socket tests exercise report and fragment boundaries, event interleaving, cancellation, timeout and oversize responses. Synchronous metadata operations skip events. A capture worker will need to consume them. |
| Verify the sensor certificate | Implemented for the advanced-security product 0x41, firmware 10.1 profile | Verifies the ECDSA/SHA-256 issuer signature and validates the P-256 subject point. Passed on a published certificate from a related 06cb:00ff reader. The Fold certificate and proof of the live peer remain unverified by this code. |
| Reuse an existing pairing | OEM worker only | A fresh OEM worker previously read HOST and opened an authenticated session with writes, formatting and new pairing disabled. The format and authorized use of the host credential still need to be established for the native worker. |
| Fresh pairing, ownership and key changes | OEM worker only | The OEM path obtained an accepted pairing. A Linux-native issuance path for a host certificate has yet to be established. The host certificate issuer and the sensor certificate issuer have different roles. |
| Secure session and authenticated commands | Full native exchange, two commands and close tested against an independent software peer | Physical acceptance of this profile, retrieval of an authorized Fold pairing and a subsequent cold reconnect remain outstanding. |
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

## Native opening handshake and host proof

The native client sends command 0x44 carrying a TLS record. It generates a fresh 32-byte random, advertises suite 0xc02e and requests a full handshake. In two public 06cb:00ff recordings the reader selected this suite, returned server version 0x0383 inside a 0x0303 record, requested an ECDSA host certificate and finished its initial flight. The client checks the message order and lengths, retains the original handshake bytes and rejects an unexpected suite, compression or certificate request. The hardware profile on the Fold still needs a direct test.

The next client flight contains the already-issued 400-byte host certificate, a fresh P-256 exchange point and a DER ECDSA/SHA-256 signature. The code checks that the signing key has the same public coordinates as the returned host certificate. It initializes the two reserved certificate-message bytes and signs all handshake messages through ClientKeyExchange, including those bytes. The signing key can remain in its OpenSSL provider.

For an independent check, the recorded signatures in both `finger2.pcapng` (frames 249, 252, 253) and `finger.pcapng` (203, 206, 207) verified over those exact plaintext handshake messages. Hashing the transcript twice failed. The native opening exchange accepted both recorded server flights and the test also splits a synthetic flight at each of its 60 internal boundaries. The host proof test uses an ephemeral test identity, verifies the generated signature, rejects an altered transcript and checks that a second exchange produces a different public point. No test credential represents a sensor-issued pairing. [USB recordings](https://github.com/vojtapl/synaTudorMiS/tree/5b3aecb3432b67083beeabdc1cfb0718513a83dd/reverse%20engineering/SP141455/Wireshark%20usb%20log)

## Authenticated session and read-only diagnostic

The native session API checks the host certificate against its key and validates the saved sensor certificate before starting the handshake. It derives separate send and receive keys from the ephemeral P-256 agreement. Both key derivations use the client random followed by the server random. The two Finished values use different labels over the same SHA-256 transcript through CertificateVerify. The client checks the reader's encrypted Finished before it returns a session handle. Each command and reply then uses a direction-specific AES-256-GCM key and sequence number. The initial implementation supports one application record per direction per command, up to 16 KiB.

The integration test runs the production C client against an independently implemented Python peer on packet sockets. The test binary substitutes a synthetic sensor certificate trust decision and an idle HID feature response. Certificate verification is tested separately using the published certificate. The peer checks the host signature and client Finished, processes two encrypted commands and acknowledges close. Preflight tests confirm an active reader and a mismatched host key produce zero HID writes. Negative cases cover a missing ChangeCipherSpec, invalid Finished with a valid tag, invalid handshake and application tags, replay, and an unexpected closing alert. A failed command publishes zero reply bytes and invalidates the session.

With an exclusively claimed reader and a pairing already provisioned for that reader, `native-inspect --paired` runs a hardware check. Pass the identified hidraw node on fd 3, its 400-byte sensor certificate on fd 4, the issued 400-byte host certificate on fd 5 and its P-256 PEM private key on fd 6. Supply credential fds from protected files through the service manager. The diagnostic requests authenticated firmware metadata, compares the reader identity with discovery, checks close_notify and verifies that the reader reports idle. A native service can pass a provider-backed signing key to the library directly. The format of the OEM worker's stored pairing and its availability through an authorized host-side interface remain unverified.

## Hardware acceptance

The next milestone is a native cold reconnect with an authorized host credential, an authenticated firmware or status request, and a clean disconnect. Then exercise separate enrollment, correct-finger verification, wrong-finger rejection, targeted deletion and cancellation through fprintd. Test a second operation immediately after the first, followed by USB reconnect. Only a physical match and rejection using the native worker can establish parity for desktop unlock.
