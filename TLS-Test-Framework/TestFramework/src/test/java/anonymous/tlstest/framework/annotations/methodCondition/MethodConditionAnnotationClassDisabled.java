/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.annotations.methodCondition;

import anonymous.tlstest.framework.annotations.MethodCondition;
import anonymous.tlstest.framework.junitExtensions.MethodConditionExtension;
import anonymous.tlstest.framework.utils.ConditionTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.RegisterExtension;


@MethodCondition(method = "classCondition")
public class MethodConditionAnnotationClassDisabled {

    @RegisterExtension
    static ConditionTest ext = new ConditionTest(MethodConditionExtension.class);

    public ConditionEvaluationResult classCondition(ExtensionContext context) {
        return ConditionEvaluationResult.disabled("");
    }

    public ConditionEvaluationResult test2(ExtensionContext context) {
        return ConditionEvaluationResult.enabled("");
    }

    public ConditionEvaluationResult disableC(ExtensionContext context) {
        return ConditionEvaluationResult.disabled("disabled");
    }

    public ConditionEvaluationResult noParameter() {
        return ConditionEvaluationResult.enabled("");
    }


    @Test
    @MethodCondition(method="test2")
    public void not_execute_validMethod() { }

    @Test
    @MethodCondition(method="disableC")
    public void not_execute_validMethod_disabled() { }

    @Test
    @MethodCondition(method="noParameter")
    public void not_execute_noParameter() { }

}
