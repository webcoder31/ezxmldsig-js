# Security policy

## Reporting a vulnerability

Report a vulnerability privately, never in a public issue, pull request or discussion: until a fix is published, a public report lets anyone exploit it.

Use the private vulnerability reporting of GitHub on the repository [webcoder31/ezxmldsig-js](https://github.com/webcoder31/ezxmldsig-js): open the tab **Security**, then **Report a vulnerability** ([direct link](https://github.com/webcoder31/ezxmldsig-js/security/advisories/new)). Only the maintainers of the repository see the report.

Describe in the report:

* the version of ezxmldsig, of Node.js, and of its OpenSSL (`node -p process.versions.openssl`);
* what an attacker can do, and under which conditions (what they must be able to submit or observe);
* the steps or the code that reproduce it, with a token if possible. Never send a private key you use outside a test.

A vulnerability that the PHP library [ezxmldsig](https://github.com/webcoder31/ezxmldsig-php) shares (the tokens and their checks are the same) can be reported on either repository.

## Supported versions

| Version | Supported |
|---|---|
| 1.x | Yes: security fixes are published as 1.x versions. |
