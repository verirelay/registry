# Security policy

## Reporting a vulnerability

Report vulnerabilities through GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open public issues, pull requests, or discussions for suspected vulnerabilities.

## Scope

Reports are in scope when they affect the code in this repository: the Registry HTTP API and its PostgreSQL store. In particular:

- Writing to `POST /v1/build-records` or `POST /v1/revocations` without an API key that matches the bcrypt `API_PWD_HASH`.
- Storing a Build Record or revocation without a valid Release Key signature over its canonical statement bytes, or with stored fields that differ from the signed statement.
- Lookups that report a revoked Build Record as not revoked, or return a `proof` that does not match the returned statement.

Read endpoints are public. Reading without an API key is not a vulnerability.

Registry holds only the Release Key public key. Signing Build Records is Release's job, so issues there belong to the [release repository](https://github.com/verirelay/release).
