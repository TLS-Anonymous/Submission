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
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import anonymous.tlstest.framework.TestContext;
import anonymous.tlstest.framework.model.DerivationScope;
import anonymous.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;

/**
 * Can be used when ever ProtocolMessageType is needed - eg. RecordContentType
 */
public class ProtocolMessageTypeDerivation extends DerivationParameter<ProtocolMessageType> {

    public ProtocolMessageTypeDerivation() {
        super(DerivationType.PROTOCOL_MESSAGE_TYPE, ProtocolMessageType.class);
    }
    
    public ProtocolMessageTypeDerivation(ProtocolMessageType selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    
    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        for(ProtocolMessageType messageType: ProtocolMessageType.values()) {
            parameterValues.add(new ProtocolMessageTypeDerivation(messageType));
        }
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
    }

}
