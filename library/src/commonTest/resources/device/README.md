# Device test fixtures

The files in this directory are **real Widevine provisioning material**. They are
git-ignored (see `.gitignore`) and must be supplied locally by whoever runs the tests.
Never commit them, and never paste their contents anywhere.

| File | What it is | Used by |
|---|---|---|
| `google_avd.wvd` | A WVD v2 device blob (Android, security level 3) | `DeviceJvmTest`, `DeviceAndroidTest`, `CDMJvmTest` |
| `google_avd.b64.txt` | The same blob, Base64-encoded | reserved for `Device.loads(String)` coverage |
| `client_id.bin` | Serialized `ClientIdentification` | `DeviceJvmTest`, `DeviceAndroidTest` |
| `private_key.pem` | The matching RSA private key, PKCS#1 PEM | `DeviceJvmTest`, `DeviceAndroidTest` |

Fixtures are loaded from the test classpath via `TestFixtures` (paths are relative to
`library/src/commonTest/resources`, e.g. `device/google_avd.wvd`). Tests that need one
print a `SKIP:` line and return when it is absent, so a checkout without these files
still produces a green — if smaller — test run.

The public DASH/HLS manifests under `../playlist/` are *not* secret and are checked in.
