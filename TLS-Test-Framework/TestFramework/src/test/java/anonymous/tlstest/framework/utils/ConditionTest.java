/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.utils;

import anonymous.tlstest.framework.junitExtensions.BaseCondition;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;

public class ConditionTest implements ExecutionCondition {
    private static final Logger LOGGER = LogManager.getLogger();
    private Class<?>[] clazzes;

    public ConditionTest(Class<?>... clazz) {
        this.clazzes = clazz;
    }

    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {

        ConditionEvaluationResult result = ConditionEvaluationResult.enabled("");

        try {
            for (Class<?> i: this.clazzes) {
                BaseCondition cls = (BaseCondition)i.newInstance();
                ConditionEvaluationResult tmp = cls.evaluateExecutionCondition(context);
                if (tmp.isDisabled()) {
                    result = tmp;
                    break;
                }
            }
        }
        catch (Exception e) {
            LOGGER.warn("Error was thrown in ConditionTest", e);
            throw new RuntimeException(e);
        }

        if (result.isDisabled() && context.getTestMethod().isPresent() && context.getRequiredTestMethod().getName().startsWith("execute")) {
            throw new RuntimeException("This test should be executed");
        }

        if (!result.isDisabled() && context.getTestMethod().isPresent() && context.getRequiredTestMethod().getName().startsWith("not_execute")) {
            throw new RuntimeException("This test should NOT be executed");
        }

        return ConditionEvaluationResult.enabled("");
    }
}
