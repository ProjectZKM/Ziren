# These are INSECURE test fixtures

`ca.key` and `ca.pem` in this directory are test PKI. **`ca.key` is committed to
a public repository**, so anybody can mint a certificate that this CA vouches
for.

Concretely: an environment that trusts `ca.pem` can be impersonated by anyone.
Network proving sends the guest ELF and the **private input stream** to the
endpoint it connects to, so an impersonated endpoint reads the witness.

## Rules

- Never point a deployment that handles real witness data at this CA. Use a
  private, per-environment CA and rotate it independently.
- `CA_CERT_PATH` is **required** when `SSL_CERT_PATH`/`SSL_KEY_PATH` are set.
  The SDK used to fall back to `ca.pem` here silently; it no longer does.
  Reaching this fixture now needs `ZKM_ALLOW_INSECURE_TEST_CA=1`, which logs a
  warning on every connection.
- `certgen.sh` defaults to this CA. That is only appropriate for local tests.
- Production packaging must exclude `ca.key`.

If a shared environment currently trusts this CA and can receive sensitive
input, rotate that environment's CA and every certificate it issued. No
production rotation is implied by the presence of these files alone — they were
always intended as fixtures — only by something real having been pointed at
them.
