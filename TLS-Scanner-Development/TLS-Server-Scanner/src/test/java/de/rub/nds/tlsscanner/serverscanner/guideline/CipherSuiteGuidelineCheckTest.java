/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CipherSuiteGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

public class CipherSuiteGuidelineCheckTest {

    @Test
    public void testPositive() {
        SiteReport report = new SiteReport("test", 443);
        report.setVersionSuitePairs(Arrays.asList(
            new VersionSuiteListPair(ProtocolVersion.TLS12,
                Collections.singletonList(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256)),
            new VersionSuiteListPair(ProtocolVersion.TLS13,
                Collections.singletonList(CipherSuite.TLS_AES_128_GCM_SHA256))));

        CipherSuiteGuidelineCheck check =
            new CipherSuiteGuidelineCheck(null, null, Collections.singletonList(ProtocolVersion.TLS12),
                Collections.singletonList(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256));
        GuidelineCheckResult result = check.evaluate(report);
        Assert.assertEquals(TestResult.TRUE, result.getResult());

        check = new CipherSuiteGuidelineCheck(null, null, Collections.singletonList(ProtocolVersion.TLS13),
            Collections.singletonList(CipherSuite.TLS_AES_128_GCM_SHA256));

        result = check.evaluate(report);
        Assert.assertEquals(TestResult.TRUE, result.getResult());
    }

    @Test
    public void testNegative() {
        SiteReport report = new SiteReport("test", 443);
        report.setVersionSuitePairs(Collections.singletonList(new VersionSuiteListPair(ProtocolVersion.TLS12,
            Arrays.asList(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384))));

        CipherSuiteGuidelineCheck check =
            new CipherSuiteGuidelineCheck(null, null, Collections.singletonList(ProtocolVersion.TLS12),
                Collections.singletonList(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256));
        GuidelineCheckResult result = check.evaluate(report);
        Assert.assertEquals(TestResult.FALSE, result.getResult());
    }
}
