# ezxmldsig for Node.js

Signed and encrypted XML tokens for Node.js: enveloping XML digital signatures that carry timestamped user data, optionally encrypted. The Node.js counterpart of the PHP library [ezxmldsig](https://github.com/webcoder31/ezxmldsig): both create and verify the same tokens, so that a single sign-on can mix PHP and Node.js nodes.

**Work in progress: the library is not usable yet, and not published.**

## Development

Requirements: Node.js 22.12 or later, and a running Docker daemon for the tests of the interoperability with the PHP library.

```sh
npm ci
npm test
```

`npm test` builds the library into `dist/`, checks the types of the sources and of the tests, and runs the tests with the test runner of Node.js.

The tests of the interoperability run the PHP library, version 1.2.0, in the official `php:8.3-cli` Docker image, through `bin/php-ezxmldsig` (see its header). The first run clones the PHP library into `test/.cache/` and installs its dependencies with Composer, in Docker. Without Docker, these tests are skipped and the test runner says why; in continuous integration (`CI=true`), they fail instead.

The certificates and keys of `test/fixtures/` are those of the PHP library. **Their private keys are public**: use them for the tests only (see the README of each directory).
