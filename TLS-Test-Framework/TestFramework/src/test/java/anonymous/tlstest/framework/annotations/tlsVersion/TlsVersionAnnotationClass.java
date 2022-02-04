/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.annotations.tlsVersion;

import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import anonymous.tlstest.framework.TestContext;
import anonymous.tlstest.framework.TestSiteReport;
import anonymous.tlstest.framework.junitExtensions.TlsVersionCondition;
import anonymous.tlstest.framework.utils.ConditionTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.ArrayList;

@TlsVersion(supported = ProtocolVersion.TLS12)
public class TlsVersionAnnotationClass {

    @RegisterExtension
    static ConditionTest ext = new ConditionTest(TlsVersionCondition.class);

    @BeforeAll
    static void setup() {
        TestContext testContext = TestContext.getInstance();
        TestSiteReport report = new TestSiteReport("");

        report.setVersions(new ArrayList<ProtocolVersion>() {
            {
                add(ProtocolVersion.TLS12);
                add(ProtocolVersion.SSL3);
            }
        });

        testContext.setSiteReport(report);
    }


    @TlsTest
    @TlsVersion(supported = ProtocolVersion.TLS12)
    public void execute_supported() { }

    @TlsTest
    public void execute_inheritedClassAnnotation() { }

    @TlsTest
    @TlsVersion(supported = ProtocolVersion.SSL3)
    public void execute_supported_overwrittenClassAnnotation() { }

    @TlsTest
    @TlsVersion(supported = ProtocolVersion.TLS13)
    public void not_execute_unsupported() { }

}
