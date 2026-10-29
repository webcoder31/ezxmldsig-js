# A P-521 signer of the seal tests: public key, never use it elsewhere

**The private key of this directory is public.** Use it for the tests only, never in an application, a test environment reachable by others, or a production system, and never trust this certificate.

The PKI of `../certs/` has no P-521 signer. This one comes from the PHP library ezxmldsig (`tests/fixtures/seal/p521/`), whose `bin/gen-seal-fixtures` issues it under the intermediate CA of `../certs/`, with the extensions of the P-384 signer and the validity of the intermediate. It is valid as long as that intermediate is: after `bin/gen-seal-test-certs`, issue it again on the side of the PHP library, and copy it here. Its key is encrypted with the password of the other signers, `signKeyPassword`.
