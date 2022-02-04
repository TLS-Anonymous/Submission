/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.model.derivationParameter.mirrored;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import anonymous.tlstest.framework.TestContext;
import anonymous.tlstest.framework.model.DerivationScope;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.model.constraint.ConditionalConstraint;
import anonymous.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import anonymous.tlstest.framework.model.derivationParameter.DerivationFactory;
import anonymous.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 *
 */
public class MirroredCipherSuiteDerivation extends MirroredDerivationParameter<CipherSuite> {

    public MirroredCipherSuiteDerivation() {
        super(DerivationType.MIRRORED_CIPHERSUITE, DerivationType.CIPHERSUITE, CipherSuite.class);
    }
    
    public MirroredCipherSuiteDerivation(CipherSuite selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }
    
    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        DerivationFactory.getInstance(getMirroredType()).getParameterValues(context, scope)
                .forEach(derivation -> parameterValues.add(new MirroredCipherSuiteDerivation(((CipherSuiteDerivation)(derivation)).getSelectedValue())));
        return parameterValues;
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CIPHERSUITE);
        condConstraints.add(new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name()).by((DerivationParameter mirroredCipherSuite, DerivationParameter cipherSuite) -> {
            if (mirroredCipherSuite.getSelectedValue().equals(cipherSuite.getSelectedValue())) {
                return false;
            }
            return true;
        })));

        return condConstraints;
    }

}
