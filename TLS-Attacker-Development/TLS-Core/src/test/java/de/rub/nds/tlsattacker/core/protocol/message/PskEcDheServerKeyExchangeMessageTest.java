/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class PskEcDheServerKeyExchangeMessageTest {

    PskEcDheServerKeyExchangeMessage message;

    @Before
    public void setUp() {
        message = new PskEcDheServerKeyExchangeMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of toString method, of class PskEcDheServerKeyExchangeMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PskEcDheServerKeyExchangeMessage:");
        sb.append("\n  Curve Type: ").append("null");
        sb.append("\n  Named Group: ").append("null");
        sb.append("\n  Public Key: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

}
