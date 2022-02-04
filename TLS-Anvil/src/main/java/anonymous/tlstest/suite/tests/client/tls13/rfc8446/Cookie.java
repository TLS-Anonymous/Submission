/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.TestDescription;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.InteroperabilityCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.testClasses.Tls13Test;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

@ClientTest
@RFC(number = 8446, section = "4.2.2 Cookie")
public class Cookie extends Tls13Test {

    @Test
    @TestDescription("Clients MUST NOT use cookies in their initial ClientHello in subsequent connections.")
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void clientHelloContainsCookieExtension() {
        int size = (int) context.getReceivedClientHelloMessage().getExtensions().stream()
                .filter(i -> Arrays.equals(ExtensionType.COOKIE.getValue(), i.getExtensionType().getValue())).count();
        if (size > 0) {
            throw new AssertionError("Regular ClientHello contains Cookie extension");
        }
    }
}
