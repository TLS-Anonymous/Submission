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
import anonymous.tlstest.framework.model.DerivationScope;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.model.constraint.ValueConstraint;
import anonymous.tlstest.framework.model.derivationParameter.DerivationFactory;
import anonymous.tlstest.framework.model.derivationParameter.DerivationParameter;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

public class ValueConstraintsConditionExtension extends BaseCondition {
    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext extensionContext) {
        if (!extensionContext.getTestMethod().isPresent()) {
            return ConditionEvaluationResult.enabled("Class annotations are not relevant.");
        }
        
        DerivationScope derivationScope = new DerivationScope(extensionContext);
        for(ValueConstraint valContraint : derivationScope.getValueConstraints()) {
            DerivationParameter derivationParam = DerivationFactory.getInstance(valContraint.getAffectedType());
            if(derivationParam.hasNoApplicableValues(TestContext.getInstance(), derivationScope)) {
                return ConditionEvaluationResult.disabled("Host does not support required value for parameter " + derivationParam.getType());
            }
        }
        
        for(DerivationType explicitType : derivationScope.getExplicitTypeValues().keySet()) {
            DerivationParameter derivationParam = DerivationFactory.getInstance(explicitType);
            if(derivationParam.hasNoApplicableValues(TestContext.getInstance(), derivationScope)) {
                return ConditionEvaluationResult.disabled("Host does not support required value for parameter " + explicitType);
            }
        }
        return ConditionEvaluationResult.enabled("");
    }
}
