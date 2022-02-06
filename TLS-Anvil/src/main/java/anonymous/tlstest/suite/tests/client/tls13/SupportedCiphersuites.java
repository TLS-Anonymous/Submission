/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.client.tls13;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.TestDescription;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.SecurityCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.testClasses.Tls13Test;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@ClientTest
@RFC(number = 8446, section = "9.3.  Protocol Invariants")
public class SupportedCiphersuites extends Tls13Test {

    @Test
    @RFC(number = 8446, section = "4.1.2.  Client Hello")
    @TestDescription("cipher_suites:  A list of the symmetric cipher options supported by " +
        "the client, specifically the record protection algorithm " +
        "(including secret key length) and a hash to be used with HKDF, in " +
        "descending order of client preference.")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    public void supportsMoreCipherSuitesThanAdvertised() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();

        List<CipherSuite> advertised = CipherSuite.getCipherSuites(clientHello.getCipherSuites().getValue());
        List<CipherSuite> supported = new ArrayList<>(context.getSiteReport().getSupportedTls13CipherSuites());

        advertised.forEach(supported::remove);

        assertEquals("Client supports more cipher suites than advertised. "
                + supported.parallelStream().map(Enum::name).collect(Collectors.joining(",")),
                0,
                supported.size());
    }
    
    @Test
    @TestDescription("For this to work, implementations MUST correctly handle extensible fields:[...] " +
        "A client sending a ClientHello MUST support all parameters " +
        "advertised in it.")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void supportsLessCipherSuitesThanAdvertised() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();
        List<CipherSuite> advertised = CipherSuite.getCipherSuites(clientHello.getCipherSuites().getValue()).stream().filter(CipherSuite::isTLS13).collect(Collectors.toList());
        List<CipherSuite> supported = new ArrayList<>(context.getSiteReport().getSupportedTls13CipherSuites());
        supported.forEach(advertised::remove);
        assertEquals("Client supports less cipher suites than advertised. Unsupported: "
                + advertised.parallelStream().map(Enum::name).collect(Collectors.joining(",")),
                0,
                advertised.size());
    }
}
