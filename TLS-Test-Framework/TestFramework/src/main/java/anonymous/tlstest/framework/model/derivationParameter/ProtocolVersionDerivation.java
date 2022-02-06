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
import java.util.List;

/**
 * This class uses byte[] instead of ProtocolVersion for more flexibility
 */
public class ProtocolVersionDerivation extends DerivationParameter<byte[]> {

    public ProtocolVersionDerivation() {
        super(DerivationType.PROTOCOL_VERSION, byte[].class);
    }

    public ProtocolVersionDerivation(byte[] selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }
    
    
    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
    }

}
