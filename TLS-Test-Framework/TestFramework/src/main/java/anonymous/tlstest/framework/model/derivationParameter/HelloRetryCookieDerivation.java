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


public class HelloRetryCookieDerivation extends DerivationParameter<byte[]> {

    public HelloRetryCookieDerivation() {
        super(DerivationType.HELLO_RETRY_COOKIE, byte[].class);
    }
    
    public HelloRetryCookieDerivation(byte[] selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> derivationParameters = new LinkedList<>();
        derivationParameters.add(new HelloRetryCookieDerivation(new byte[] {0x55}));
        derivationParameters.add(new HelloRetryCookieDerivation(new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}));
        derivationParameters.add(new HelloRetryCookieDerivation(new byte[] {(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF}));
        derivationParameters.add(new HelloRetryCookieDerivation(new byte[] {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,}));
        return derivationParameters;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        config.setDefaultExtensionCookie(getSelectedValue());
    }
    
}
