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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import anonymous.tlstest.framework.TestContext;
import anonymous.tlstest.framework.model.DerivationScope;
import anonymous.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;

public class GreaseProtocolVersionDerivation extends DerivationParameter<ProtocolVersion> {

    public GreaseProtocolVersionDerivation() {
        super(DerivationType.GREASE_PROTOCOL_VERSION, ProtocolVersion.class);
    }
    
    public GreaseProtocolVersionDerivation(ProtocolVersion selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }
    
    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        for(ProtocolVersion version : ProtocolVersion.values()) {
            if(version.isGrease()) {
                parameterValues.add(new GreaseProtocolVersionDerivation(version));
            }
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
    }
    
}
