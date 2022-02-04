/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.both.tls12.rfc5246;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.TestDescription;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.SecurityCategory;
import anonymous.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.testClasses.Tls12Test;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import org.junit.jupiter.api.Test;

@RFC(number = 5246, section = "1.2 Major Differences from TLS 1.1")
public class CipherSuites extends Tls12Test {

    @Test
    @SecurityCategory(SeverityLevel.CRITICAL)
    @TestDescription("Removed IDEA and DES cipher suites. They are now deprecated and will be documented in a separate document.")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @DeprecatedFeatureCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void supportOfDeprecatedCipherSuites() {
        List<VersionSuiteListPair> versionSuiteListPairList = context.getSiteReport().getVersionSuitePairs();
        List<CipherSuite> suites = versionSuiteListPairList.stream()
                .filter(i -> i.getVersion() == ProtocolVersion.TLS12)
                .flatMap(i -> i.getCipherSuiteList().stream())
                .collect(Collectors.toList());

        List<String> badSuites = new ArrayList<>();
        for (CipherSuite i : suites) {
            if (AlgorithmResolver.getCipher(i).toString().contains("IDEA")) {
                badSuites.add(i.toString());
            }
            else if (AlgorithmResolver.getCipher(i).toString().contains("_DES")) {
                badSuites.add(i.toString());
            }
            else if (AlgorithmResolver.getCipher(i).toString().contains("RC4")) {
                badSuites.add(i.toString());
            }
        }

        assertEquals("Deprecated Ciphersuites supported: " + String.join(", ", badSuites), 0, badSuites.size());
    }
}
