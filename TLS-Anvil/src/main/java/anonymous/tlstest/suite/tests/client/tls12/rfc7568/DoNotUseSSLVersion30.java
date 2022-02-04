/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.client.tls12.rfc7568;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.TestDescription;
import anonymous.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.SecurityCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.testClasses.Tls12Test;

import java.util.Arrays;

import static org.junit.Assert.*;

import org.junit.jupiter.api.Test;

@RFC(number = 7568, section = "3. Do Not Use SSL Version 3.0")
@ClientTest
public class DoNotUseSSLVersion30 extends Tls12Test {

    @Test
    @TestDescription("SSLv3 MUST NOT be used. Negotiation of SSLv3 from "
            + "any version of TLS MUST NOT be permitted. [...]"
            + "Pragmatically, clients MUST NOT send a ClientHello with "
            + "ClientHello.client_version set to {03,00}.")
    @SecurityCategory(SeverityLevel.CRITICAL)
    @DeprecatedFeatureCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    public void sendClientHelloVersion0300() {
        ClientHelloMessage clientHelloMessage = context.getReceivedClientHelloMessage();
        assertFalse("ClientHello contains protocol version 0300",
                Arrays.equals(ProtocolVersion.SSL3.getValue(), clientHelloMessage.getProtocolVersion().getValue())
        );
    }
}
