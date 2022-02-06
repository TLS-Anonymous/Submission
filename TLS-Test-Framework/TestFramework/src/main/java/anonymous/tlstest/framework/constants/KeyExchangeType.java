/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.constants;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.annotation.Nonnull;

public enum KeyExchangeType {
    RSA,
    DH,
    ECDH,
    ALL12,
    ALL13,
    NOT_SPECIFIED;

    private static final Logger LOGGER = LogManager.getLogger();


    public boolean compatibleWithCiphersuite(CipherSuite i) {
        try {
            KeyExchangeAlgorithm alg = AlgorithmResolver.getKeyExchangeAlgorithm(i);
            switch (this) {
                case RSA:
                    return alg != null && alg.isKeyExchangeRsa();
                case DH:
                    return alg != null && alg.isKeyExchangeDh();
                case ECDH:
                    return alg != null && alg.isKeyExchangeEcdh();
                case ALL12:
                    return AlgorithmResolver.getKeyExchangeAlgorithm(i) != null;
                case ALL13:
                    return AlgorithmResolver.getKeyExchangeAlgorithm(i) == null;
                case NOT_SPECIFIED:
                    return false;
            }
        } catch (UnsupportedOperationException ignored) {

        }

        return false;
    }

    @Nonnull
    public static KeyExchangeType forCipherSuite(CipherSuite i) {
        try {
            KeyExchangeAlgorithm alg = AlgorithmResolver.getKeyExchangeAlgorithm(i);
            if (alg == null) {
                return KeyExchangeType.ALL13;
            }

            if (alg.isKeyExchangeEcdh()) return KeyExchangeType.ECDH;
            if (alg.isKeyExchangeRsa()) return KeyExchangeType.RSA;
            if (alg.isKeyExchangeDh()) return KeyExchangeType.DH;
        } catch (UnsupportedOperationException ignored) {

        }

        return KeyExchangeType.NOT_SPECIFIED;
    }


}
