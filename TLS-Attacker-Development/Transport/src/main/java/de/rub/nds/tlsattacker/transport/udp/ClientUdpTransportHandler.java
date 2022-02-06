/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.transport.udp;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.udp.stream.UdpInputStream;
import de.rub.nds.tlsattacker.transport.udp.stream.UdpOutputStream;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.DatagramSocket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientUdpTransportHandler extends UdpTransportHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String hostname;

    public ClientUdpTransportHandler(Connection connection) {
        super(connection.getFirstTimeout(), connection.getTimeout(), ConnectionEndType.CLIENT);
        this.hostname = connection.getHostname();
        this.port = connection.getPort();
    }

    public ClientUdpTransportHandler(long firstTimeout, long timeout, String hostname, int port) {
        super(firstTimeout, timeout, ConnectionEndType.CLIENT);
        this.hostname = hostname;
        this.port = port;
    }

    @Override
    public void preInitialize() throws IOException {
        // Nothing to do here
    }

    @Override
    public void initialize() throws IOException {
        LOGGER.debug("Initializing ClientUdpTransportHandler host: {}, port: {}", hostname, port);
        socket = new DatagramSocket();
        socket.setSoTimeout((int) timeout);
        cachedSocketState = null;
        setStreams(new PushbackInputStream(new UdpInputStream(socket, true)),
            new UdpOutputStream(socket, hostname, port));
    }

}
