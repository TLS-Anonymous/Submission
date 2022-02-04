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

public class KexAnnotationTLS13 {

    @RegisterExtension
    static ConditionTest ext = new ConditionTest(KexCondition.class);

    @BeforeAll
    static void setup() {
        TestContext testContext = TestContext.getInstance();
        TestSiteReport report = new TestSiteReport("");

        report.addCipherSuites(new HashSet<CipherSuite>(){
            {
                add(CipherSuite.TLS_AES_256_GCM_SHA384);
            }
        });

        testContext.setSiteReport(report);
    }


    @TlsTest
    @KeyExchange(supported = KeyExchangeType.ALL13)
    public void execute_supported() {}

    @TlsTest
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void not_execute_unsupported() {}

}
