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

@TlsVersion(supported = ProtocolVersion.TLS13)
@KeyExchange(supported = KeyExchangeType.ALL13)
@Tag("tls13")
public class Tls13Test extends TlsBaseTest {
    @Override
    public Config getConfig() {
        return context.getConfig().createTls13Config();
    }
}
