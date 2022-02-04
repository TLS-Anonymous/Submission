/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package anonymous.tlstest.framework.model.constraint;

import anonymous.tlstest.framework.model.derivationParameter.DerivationFactory;
import anonymous.tlstest.framework.TestContext;
import anonymous.tlstest.framework.model.DerivationScope;
import anonymous.tlstest.framework.model.DerivationType;
import de.rwth.swc.coffee4j.model.constraints.Constraint;
import java.util.List;
import java.util.Set;

public class ConditionalConstraint {
    private final Set<DerivationType> requiredDerivations;
    private final Constraint constraint;

    public Set<DerivationType> getRequiredDerivations() {
        return requiredDerivations;
    }

    public Constraint getConstraint() {
        return constraint;
    }
    
    public boolean isApplicableTo(List<DerivationType> modeledDerivations, DerivationScope scope) {
        for(DerivationType required: requiredDerivations) {
            if(!modeledDerivations.contains(required) || !DerivationFactory.getInstance(required).canBeModeled(TestContext.getInstance(), scope)) {
                return false;
            }
        }
        return true;
    }

    public ConditionalConstraint(Set<DerivationType> requiredDerivations, Constraint constraint) {
        this.requiredDerivations = requiredDerivations;
        this.constraint = constraint;
    }
    
    
}
