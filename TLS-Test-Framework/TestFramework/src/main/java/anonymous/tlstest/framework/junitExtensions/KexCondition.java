/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.junitExtensions;

import anonymous.tlstest.framework.annotations.KeyExchange;
import anonymous.tlstest.framework.constants.KeyX;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;


/**
 * Evaluates the KeyExchange annotation and disables a test
 * if the target does not support cipher suites that the KeyExchange annotation requires.
 */
public class KexCondition extends BaseCondition {
    private static final Logger LOGGER = LogManager.getLogger();


    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext extensionContext) {
        if (!extensionContext.getTestMethod().isPresent()) {
            return ConditionEvaluationResult.enabled("Class annotations are not relevant.");
        }

        KeyExchange resolvedKeyExchange = KeyX.resolveKexAnnotation(extensionContext);

        if (resolvedKeyExchange.supported().length > 0) {
            return ConditionEvaluationResult.enabled("Target supports Ciphersuites that are supported by the test.");
        }
        else {
            return ConditionEvaluationResult.disabled("Target does not provide Ciphersuites that are supported by the test.");
        }

    }
}
