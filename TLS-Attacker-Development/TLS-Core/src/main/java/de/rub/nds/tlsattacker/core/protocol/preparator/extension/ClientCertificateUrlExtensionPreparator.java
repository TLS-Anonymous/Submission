/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateUrlExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ClientCertificateUrlExtensionPreparator extends ExtensionPreparator<ClientCertificateUrlExtensionMessage> {

    public ClientCertificateUrlExtensionPreparator(Chooser chooser, ClientCertificateUrlExtensionMessage message,
        ExtensionSerializer<ClientCertificateUrlExtensionMessage> serializer) {
        super(chooser, message, serializer);
    }

    @Override
    public void prepareExtensionContent() {
        // nothing to prepare here, since it's an opt-in extension
    }

}
