/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.TruncatedHmacExtensionMessage;

public class TruncatedHmacExtensionSerializer extends ExtensionSerializer<TruncatedHmacExtensionMessage> {

    public TruncatedHmacExtensionSerializer(TruncatedHmacExtensionMessage message) {
        super(message);
    }

    @Override
    public byte[] serializeExtensionContent() {
        return getAlreadySerialized();
    }

}