/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.config;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;

public class GeneralDrownCommandConfig extends BaseDrownCommandConfig {

    public static final String COMMAND = "generalDrown";

    public GeneralDrownCommandConfig(GeneralDelegate delegate) {
        super(delegate);
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        return config;
    }

}
