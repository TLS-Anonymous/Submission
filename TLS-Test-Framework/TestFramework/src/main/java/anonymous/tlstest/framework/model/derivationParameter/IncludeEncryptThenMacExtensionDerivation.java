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
import anonymous.tlstest.framework.TestContext;
import anonymous.tlstest.framework.model.DerivationScope;
import anonymous.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;

public class IncludeEncryptThenMacExtensionDerivation extends DerivationParameter<Boolean> {

    public IncludeEncryptThenMacExtensionDerivation() {
        super(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION, Boolean.class);
    }
    
    public IncludeEncryptThenMacExtensionDerivation(Boolean selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }
    
    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        parameterValues.add(new IncludeEncryptThenMacExtensionDerivation(true));
        parameterValues.add(new IncludeEncryptThenMacExtensionDerivation(false));
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        config.setAddEncryptThenMacExtension(getSelectedValue());
    }

}
