/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsscanner.serverscanner.guideline.checks.AnalyzedPropertyGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import org.junit.Assert;
import org.junit.Test;

public class ConditionalGuidelineCheckTest {

    @Test
    public void testPositive() {
        SiteReport report = new SiteReport("test", 443);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_PSK, false);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3, true);

        GuidelineCheckCondition condition =
            new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE);
        AnalyzedPropertyGuidelineCheck check = new AnalyzedPropertyGuidelineCheck(null, null, condition,
            AnalyzedProperty.SUPPORTS_TLS13_PSK, TestResult.TRUE);

        GuidelineCheckResult result = null;

        if (check.passesCondition(report)) {
            result = check.evaluate(report);
        }

        Assert.assertNotNull(result);
        Assert.assertEquals(TestResult.FALSE, result.getResult());
    }

    @Test
    public void testNegative() {
        SiteReport report = new SiteReport("test", 443);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_PSK, false);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS_1_3, false);

        GuidelineCheckCondition condition =
            new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE);
        AnalyzedPropertyGuidelineCheck check = new AnalyzedPropertyGuidelineCheck(null, null, condition,
            AnalyzedProperty.SUPPORTS_TLS13_PSK, TestResult.TRUE);

        GuidelineCheckResult result = null;

        if (check.passesCondition(report)) {
            result = check.evaluate(report);
        }

        Assert.assertNull(result);
    }
}
