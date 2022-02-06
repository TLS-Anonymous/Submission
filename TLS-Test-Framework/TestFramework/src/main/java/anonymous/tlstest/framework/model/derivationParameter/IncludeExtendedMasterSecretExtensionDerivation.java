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

/**
 *
 */
public class IncludeExtendedMasterSecretExtensionDerivation extends DerivationParameter<Boolean> {

    public IncludeExtendedMasterSecretExtensionDerivation() {
        super(DerivationType.INCLUDE_EXTENDED_MASTER_SECRET_EXTENSION, Boolean.class);
    }
    public IncludeExtendedMasterSecretExtensionDerivation(Boolean selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        parameterValues.add(new IncludeExtendedMasterSecretExtensionDerivation(true));
        parameterValues.add(new IncludeExtendedMasterSecretExtensionDerivation(false));
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        config.setAddExtendedMasterSecretExtension(getSelectedValue());
    }

}
