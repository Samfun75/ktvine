# Device test fixtures

Everything under this directory is **real DRM provisioning material**. It is git-ignored
(see `.gitignore`) and must be supplied locally by whoever runs the tests. Never commit it,
and never paste its contents anywhere. Only the `README.md` files are tracked.

```
device/
  widevine/    Widevine device — used by the test suite today
  playready/   PlayReady devices — see the caveat below
```

## widevine/

A real Widevine device, loaded through the test classpath by `TestFixtures` (paths are
relative to `library/src/commonTest/resources`, e.g. `device/widevine/google_avd.wvd`).

| File | What it is | Used by |
|---|---|---|
| `google_avd.wvd` | A WVD v2 device blob (Android, security level 3) | `DeviceJvmTest`, `DeviceAndroidTest`, `CDMJvmTest` |
| `google_avd.b64.txt` | The same blob, Base64-encoded | reserved for `Device.loads(String)` coverage |
| `client_id.bin` | Serialized `ClientIdentification` | `DeviceJvmTest`, `DeviceAndroidTest` |
| `private_key.pem` | The matching RSA private key, PKCS#1 PEM | `DeviceJvmTest`, `DeviceAndroidTest` |

Tests that need one print a `SKIP:` line and return when it is absent, so a checkout without
these files still produces a green — if smaller — test run.

## playready/

Several PlayReady SL3000 devices, each a folder of `.prd` / `bgroupcert.dat` / `zgpriv.dat`
files. **ktvine cannot currently use these.** It has no PlayReady CDM — no device
provisioning, no XMR license parsing, no ECC P-256, no license acquisition — so a `.prd`
device buys nothing today. ktvine's PlayReady support is header-only: parse a PlayReady
Object for its KIDs, and convert Widevine ⇄ PlayReady, none of which needs a device.

Using them would mean building a PlayReady CDM (device provisioning, XMR licenses, ECC
P-256) — a separate effort that does not exist yet. Until then, nothing in the test suite
reads this folder; keep the devices here for whoever picks that work up.

The public DASH/HLS manifests under `../playlist/` are *not* secret and are checked in.
