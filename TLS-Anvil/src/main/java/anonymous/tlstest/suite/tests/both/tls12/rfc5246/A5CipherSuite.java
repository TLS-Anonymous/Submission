/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.both.tls12.rfc5246;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.TestDescription;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.SecurityCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.testClasses.Tls12Test;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;


@RFC(number = 5246, section = "A.5. The Cipher Suite")
public class A5CipherSuite extends Tls12Test {

    @Test
    @SecurityCategory(SeverityLevel.CRITICAL)
    @TestDescription("TLS_NULL_WITH_NULL_NULL is specified and is the initial state of a " +
        "TLS connection during the first handshake on that channel, but MUST " +
        "NOT be negotiated, as it provides no more protection than an " +
        "unsecured connection.")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void negotiateTLS_NULL_WITH_NULL_NULL() {
        List<CipherSuite> suites = new ArrayList<>(context.getSiteReport().getCipherSuites());
        if (suites.contains(CipherSuite.TLS_NULL_WITH_NULL_NULL)) {
            throw new AssertionError("TLS_NULL_WITH_NULL_NULL ciphersuite is supported");
        }
    }

    /*@TlsTest(description = "These cipher suites MUST NOT be used by TLS 1.2 implementations unless the application " +
            "layer has specifically requested to allow anonymous key exchange", securitySeverity = SeverityLevel.HIGH)*/
    @Test
    @SecurityCategory(SeverityLevel.CRITICAL)
    @TestDescription("These " +
        "cipher suites MUST NOT be used by TLS 1.2 implementations unless the " +
        "application layer has specifically requested to allow anonymous key " +
        "exchange.")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void anonCipherSuites() {
        List<CipherSuite> suites = new ArrayList<>(context.getSiteReport().getCipherSuites());
        List<CipherSuite> forbidden = CipherSuite.getImplemented();
        forbidden.removeIf(i -> !i.toString().contains("_anon_"));

        List<String> errors = new ArrayList<>();
        for (CipherSuite i : forbidden) {
            if (suites.contains(i)) {
                errors.add(i.toString());
            }
        }

        if (errors.size() > 0) {
            throw new AssertionError(String.format("The following ciphersuites should not be supported: %s", String.join(", ", errors)));
        }
    }


}
