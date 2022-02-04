/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.testClasses;

import anonymous.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import anonymous.tlstest.framework.annotations.KeyExchange;
import anonymous.tlstest.framework.constants.KeyExchangeType;
import org.junit.jupiter.api.Tag;

@TlsVersion(supported = ProtocolVersion.TLS12)
@KeyExchange(supported = KeyExchangeType.ALL12)
@Tag("tls12")
public class Tls12Test extends TlsBaseTest {
    @Override
    public Config getConfig() {
        Config baseConfig = context.getConfig().createConfig();
        return baseConfig;
    }  
}
