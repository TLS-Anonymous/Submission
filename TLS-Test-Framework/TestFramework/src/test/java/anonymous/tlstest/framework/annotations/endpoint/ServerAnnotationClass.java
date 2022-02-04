/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.annotations.endpoint;

import anonymous.tlstest.framework.TestContext;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.ServerTest;
import anonymous.tlstest.framework.junitExtensions.EndpointCondition;
import anonymous.tlstest.framework.utils.ConditionTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.RegisterExtension;

@ServerTest
public class ServerAnnotationClass {

    @RegisterExtension
    static ConditionTest ext = new ConditionTest(EndpointCondition.class);

    @BeforeAll
    static void setup() {
        TestContext testContext = TestContext.getInstance();
        testContext.getConfig().parse(new String[]{ "client", "-port", "443" });
    }

    @ClientTest
    public void execute_supportedForConfig() { }

    @TlsTest
    public void not_execute_inheritedClassAnnotation() { }

    @ServerTest
    public void not_execute_unsupportedModeForConfig() { }

}
