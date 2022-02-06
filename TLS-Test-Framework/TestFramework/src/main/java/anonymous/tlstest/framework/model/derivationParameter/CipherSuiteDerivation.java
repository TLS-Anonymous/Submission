/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import anonymous.tlstest.framework.TestContext;
import anonymous.tlstest.framework.constants.TestEndpointType;
import anonymous.tlstest.framework.model.DerivationScope;
import anonymous.tlstest.framework.model.DerivationType;

import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class CipherSuiteDerivation extends DerivationParameter<CipherSuite> {
    
    public CipherSuiteDerivation() {
        super(DerivationType.CIPHERSUITE, CipherSuite.class);
    }
    
    public CipherSuiteDerivation(CipherSuite selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        if(context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            config.setDefaultClientSupportedCipherSuites(getSelectedValue());
        } else {
            config.setDefaultServerSupportedCipherSuites(getSelectedValue());
        }
        config.setDefaultSelectedCipherSuite(getSelectedValue());
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        Set<CipherSuite> cipherSuiteList = context.getSiteReport().getCipherSuites();
        cipherSuiteList.addAll(context.getSiteReport().getSupportedTls13CipherSuites());
        for (CipherSuite cipherSuite : cipherSuiteList) {
            if(scope.getKeyExchangeRequirements().compatibleWithCiphersuite(cipherSuite)) {
                parameterValues.add(new CipherSuiteDerivation(cipherSuite));
            }
        }
        
        return parameterValues;
    }
    
}
