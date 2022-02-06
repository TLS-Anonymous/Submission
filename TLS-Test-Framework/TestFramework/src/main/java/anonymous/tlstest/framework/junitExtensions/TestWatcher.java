/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.junitExtensions;

import anonymous.tlstest.framework.TestContext;
import anonymous.tlstest.framework.constants.TestResult;
import anonymous.tlstest.framework.execution.AnnotatedState;
import anonymous.tlstest.framework.execution.AnnotatedStateContainer;
import anonymous.tlstest.framework.utils.ExecptionPrinter;
import anonymous.tlstest.framework.utils.Utils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import javax.annotation.Nullable;
import java.util.Optional;

/**
 * The class contains methods that are called when a test case terminates.
 * If no AnnotatedStateContainer is associated with the finished test case
 * a new container is created.
 *
 * Be careful: For the last test case, these methods are called after
 * AnnotatedStateContainer.finished, therefore the container is already removed
 * from the TestContext.
 */
public class TestWatcher implements org.junit.jupiter.api.extension.TestWatcher {
    private static final Logger LOGGER = LogManager.getLogger();

    @Nullable
    private AnnotatedStateContainer createResult(ExtensionContext context, TestResult result) {

        String uniqueId = Utils.getTemplateContainerExtensionContext(context).getUniqueId();
        AnnotatedStateContainer container = TestContext.getInstance().getTestResults().get(uniqueId);

        // Do not repplace || with && :D
        if (container != null || TestContext.getInstance().testIsFinished(uniqueId)) {
            // could be null, if AnnotatedStateContainer.finished was called before
            // see note above
            return container;
        }

        container = AnnotatedStateContainer.forExtensionContext(context);
        container.setResultRaw(result.getValue());
        TestContext.getInstance().addTestResult(container);
        return container;
    }


    @Override
    synchronized public void testSuccessful(ExtensionContext context) {
        TestContext.getInstance().testSucceeded();
        AnnotatedStateContainer container = createResult(context, TestResult.SUCCEEDED);

        if (!Utils.extensionContextIsBasedOnCombinatorialTesting(context.getParent().get())) {
            // test does not belong to a test case performing handshakes
            // thus AnnotatedStateContainer.finished is never called,
            // therefore serialze the container immediately
            container.finished();
        }
    }

    @Override
    synchronized public void testFailed(ExtensionContext context, Throwable cause) {
        TestContext.getInstance().testFailed();

        if (!(cause instanceof AssertionError)) {
            LOGGER.error("Test failed without AssertionError {}\n", context.getDisplayName(), cause);
        }

        String uniqueId = Utils.getTemplateContainerExtensionContext(context).getUniqueId();
        AnnotatedStateContainer container = createResult(context, TestResult.FAILED);
        if (container == null && TestContext.getInstance().testIsFinished(uniqueId))
            return;
        else if (container == null) {
            LOGGER.error("This should not happen... AnnotatedStateContainer is null but Test is not finished yet");
        }

        AnnotatedState state = container.getStates().stream()
                .filter(i -> i.getExtensionContext().getUniqueId().equals(context.getUniqueId()))
                .findFirst()
                .orElse(null);

        if (state == null) {
            if (Utils.extensionContextIsBasedOnCombinatorialTesting(context.getParent().get())) {
                state = new AnnotatedState(context, null, null);
                state.setFailedReason(cause);
            } else {
                // test does not belong to a test case performing handshakes
                // thus AnnotatedStateContainer.finished is never called,
                // therefore serialze the container immediately
                container.setFailedReason(ExecptionPrinter.stacktraceToString(cause));
                container.finished();
            }
        }
    }

    @Override
    synchronized public void testDisabled(ExtensionContext context, Optional<String> reason) {
        TestContext.getInstance().testDisabled();
        AnnotatedStateContainer container = createResult(context, TestResult.DISABLED);
        container.setDisabledReason(reason.orElse("No reason"));
        if (!Utils.extensionContextIsBasedOnCombinatorialTesting(context.getParent().get())) {
            // test does not belong to a test case performing handshakes
            // thus AnnotatedStateContainer.finished is never called,
            // therefore serialze the container immediately
            container.finished();
        }
    }
}
