# Test keys: public, never use them elsewhere

**The private keys of this directory are public.** They are published with the source code of this library, and with that of the PHP library ezxmldsig, which shares them: anyone who has either library has them. `sign.key.pem` (password `signKeyPassword`) lets anyone sign tokens that a receiver trusting `intermediate.cert.pem` and `root.cert.pem` accepts, and `crypt.key.pem` (no password) lets anyone decrypt the tokens encrypted with `crypt.cert.pem`.

Use these files for the tests only. Never use them, nor trust these CA certificates, in an application, a test environment reachable by others, or a production system: generate your own keys and certificates, and keep the private keys out of any repository.

The files are copied from `tests/fixtures/certs/` of the PHP library [ezxmldsig](https://github.com/webcoder31/ezxmldsig), version 1.2.0, which generates them with `bin/gen-test-certs`. Every certificate is valid for 10 years from its generation: copy them again from there when they expire.

| File | Content |
|---|---|
| `root.cert.pem`, `root.key.pem` | Root CA certificate (self-signed), and its private key |
| `intermediate.cert.pem`, `intermediate.key.pem` | Intermediate CA certificate, issued by the root, and its private key |
| `sign.cert.pem`, `sign.key.pem` | Signing certificate issued by the intermediate CA, and its private key (password `signKeyPassword`) |
| `crypt.cert.pem`, `crypt.key.pem` | Encryption certificate issued by the intermediate CA, and its private key (no password) |
| `attacker.cert.pem`, `attacker.key.pem` | Certificate signed by its own key, whose subject and issuer names copy those of `sign.cert.pem` |
