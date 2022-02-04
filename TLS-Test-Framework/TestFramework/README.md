# TLS-Test-Framework

The TLS-Test-Framework powers the [TLS-Anvil](https://github.com/***/TLS-Testsuite).

The framework provides JUnit extensions, annotations and an API for modeling tests for the TLS protocol. It uses the TLS stack of [TLS-Attacker](https://github.com/***/TLS-Attacker) for the execution of handshake workflows that are defined in test cases.


## Connected Projects
* [TLS-Testsuite](https://github.com/***/TLS-Testsuite)
* [TLS-Testsuite-Report-Analyzer](https://github.com/***/TLS-Testsuite-Report-Analyzer)
* [TLS-Testsuite-Large-Scale-Evaluator](https://github.com/***/TLS-Testsuite-Large-Scale-Evaluator)

## Features
* Client and Server testing
* Automated client testing 
    * Provide a shell command that is executed to trigger the client
* Parallel test execution
    * Tests TLS handshakes are executed in parallel
* Conditional test execution based on annotations
* Automatic test derivation
* Test report generation (JSON and XML)
* Command-line interface definition for configuring...
    * ... parallelism
    * ... target
* Complex handshake validation
