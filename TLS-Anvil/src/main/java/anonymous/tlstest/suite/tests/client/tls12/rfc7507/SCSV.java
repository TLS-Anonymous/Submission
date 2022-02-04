/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package anonymous.tlstest.suite.tests.client.tls12.rfc7507;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.TestDescription;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.SecurityCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.testClasses.Tls12Test;
import java.util.List;
import static org.junit.Assert.assertFalse;
import org.junit.jupiter.api.Tag;

import org.junit.jupiter.api.Test;

@ClientTest
@RFC(number = 7507, section = "4. Client Behavior")
public class SCSV extends Tls12Test {
    @Test
    @TestDescription("If a client sets ClientHello.client_version to its highest " +
        "supported protocol version, it MUST NOT include TLS_FALLBACK_SCSV " +
        "in ClientHello.cipher_suites.")
    @SecurityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void doesNotIncludeFallbackCipherSuite() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();

        List<CipherSuite> advertised = CipherSuite.getCipherSuites(clientHello.getCipherSuites().getValue());
        assertFalse("Client included TLS_FALLBACK_SCSV in its first ClientHello", advertised.contains(CipherSuite.TLS_FALLBACK_SCSV));
    }
}
