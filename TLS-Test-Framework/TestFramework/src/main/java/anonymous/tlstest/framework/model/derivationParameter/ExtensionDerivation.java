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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import anonymous.tlstest.framework.TestContext;
import anonymous.tlstest.framework.model.DerivationScope;
import anonymous.tlstest.framework.model.DerivationType;
import java.util.List;

/**
 *
 */
public class ExtensionDerivation extends DerivationParameter<ExtensionType> {
    
    public ExtensionDerivation() {
        super(DerivationType.EXTENSION, ExtensionType.class);
    }
    
    public ExtensionDerivation(ExtensionType selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        //currently this is only used for explicitly listed (unrequested) extensions
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        //currently this is only used for explicitly listed (unrequested) extensions
    }

}
