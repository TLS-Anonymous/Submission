# TLS-Testsuite

The TLS-Testsuite is powered by the [TLS-Test-Framework](https://github.com/***/TLS-Test-Framework)

The Testsuite contains around 175 client and server tests for TLS 1.2 and TLS 1.3 covering the following RFCs:
* RFC 4492 - Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS)
* RFC 5246 - The Transport Layer Security (TLS) Protocol Version 1.2
* RFC 6066 - Transport Layer Security (TLS) Extensions: Extension Definitions
* RFC 6176 - Prohibiting Secure Sockets Layer (SSL) Version 2.0
* RFC 7366 - Encrypt-then-MAC for Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
* RFC 7465 - Prohibiting RC4 Cipher Suites
* RFC 7507 - TLS Fallback Signaling Cipher Suite Value (SCSV) for Preventing Protocol Downgrade Attacks
* RFC 7568 - Deprecating Secure Sockets Layer Version 3.0
* RFC 7685 - A Transport Layer Security (TLS) ClientHello Padding Extension
* RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3
* RFC 8701 - Applying Generate Random Extensions And Sustain Extensibility (GREASE) to TLS Extensibility

`./annotations` contains an overview of the tested RFC requirements.

## Connected Projects
* [TLS-Test-Framework](https://github.com/***/TLS-Test-Framework)
* [TLS-Testsuite-Report-Analyzer](https://github.com/***/TLS-Testsuite-Report-Analyzer)
* [TLS-Testsuite-Large-Scale-Evaluator](https://github.com/***/TLS-Testsuite-Large-Scale-Evaluator)

## Run
```
docker run --rm -it testsuite --help
```

