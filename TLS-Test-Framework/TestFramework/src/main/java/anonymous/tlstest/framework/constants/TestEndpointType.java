/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.constants;

public enum TestEndpointType {
    CLIENT("client"),
    SERVER("server"),
    BOTH("both");

    private final String mode;

    TestEndpointType(final String mode) {
        this.mode = mode;
    }

    @Override
    public String toString() {
        return this.mode;
    }
}
