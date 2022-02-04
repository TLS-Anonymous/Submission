/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.simpleTest;

import anonymous.tlstest.framework.execution.AnnotatedStateContainer;
import org.junit.jupiter.api.extension.AfterTestExecutionCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 *
 */
public class SimpleTestExecutionCallback implements AfterTestExecutionCallback {

    public SimpleTestExecutionCallback() {
    }

    @Override
    public void afterTestExecution(ExtensionContext extensionContext) throws Exception {
        SimpleTestManager testManager = SimpleTestManagerContainer.getInstance().getManagerByExtension(extensionContext);
        testManager.testCompleted();
        if(testManager.allTestsFinished()) {
            AnnotatedStateContainer.forExtensionContext(extensionContext).finished();
        }
    }

}
