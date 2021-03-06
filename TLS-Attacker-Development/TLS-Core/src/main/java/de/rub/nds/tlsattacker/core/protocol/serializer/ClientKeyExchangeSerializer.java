/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;

/**
 * @param <T>
 *            The KeyExchangeMessage that should be serialized
 */
public abstract class ClientKeyExchangeSerializer<T extends ClientKeyExchangeMessage>
    extends HandshakeMessageSerializer<T> {

    /**
     * Constructor for the ClientKeyExchangeSerializer
     *
     * @param message
     *                Message that should be serialized
     * @param version
     *                Version of the Protocol
     */
    public ClientKeyExchangeSerializer(T message, ProtocolVersion version) {
        super(message, version);
    }

}
