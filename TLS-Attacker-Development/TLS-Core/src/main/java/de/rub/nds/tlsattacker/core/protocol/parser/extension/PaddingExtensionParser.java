/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PaddingExtensionParser extends ExtensionParser<PaddingExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PaddingExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array, config);
    }

    @Override
    public void parseExtensionMessageContent(PaddingExtensionMessage msg) {
        msg.setPaddingBytes(parseByteArrayField(msg.getExtensionLength().getValue()));
        LOGGER
            .debug("The padding extension parser parsed the padding bytes " + bytesToHexString(msg.getPaddingBytes()));
    }

    @Override
    protected PaddingExtensionMessage createExtensionMessage() {
        return new PaddingExtensionMessage();
    }

}
