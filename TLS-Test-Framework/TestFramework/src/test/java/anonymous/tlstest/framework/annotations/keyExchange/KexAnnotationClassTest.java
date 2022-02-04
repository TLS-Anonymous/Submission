/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.annotations.keyExchange;

import anonymous.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import anonymous.tlstest.framework.TestContext;
import anonymous.tlstest.framework.TestSiteReport;
import anonymous.tlstest.framework.annotations.KeyExchange;
import anonymous.tlstest.framework.constants.KeyExchangeType;
import anonymous.tlstest.framework.junitExtensions.KexCondition;
import anonymous.tlstest.framework.utils.ConditionTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.HashSet;


@KeyExchange(supported = KeyExchangeType.ECDH)
public class KexAnnotationClassTest {

    @RegisterExtension
    static ConditionTest ext = new ConditionTest(KexCondition.class);

    @BeforeAll
    static void setup() {
        TestContext testContext = TestContext.getInstance();
        TestSiteReport report = new TestSiteReport("");

        report.addCipherSuites(new HashSet<CipherSuite>(){
            {
                add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
            }
        });

        testContext.setSiteReport(report);
    }

    @TlsTest
    public void execute_inheritedClassAnnoation() { }

    @TlsTest
    @KeyExchange(supported = {}, mergeSupportedWithClassSupported = true)
    public void execute_mergedWithClassAnnoation() { }

    @TlsTest
    @KeyExchange(supported = KeyExchangeType.DH)
    public void not_execute_unsupprtedKex() { }

}
