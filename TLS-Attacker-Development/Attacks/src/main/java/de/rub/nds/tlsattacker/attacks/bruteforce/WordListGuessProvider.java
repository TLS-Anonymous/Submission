/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.bruteforce;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * A GuessProvider based on a WordList. It reads bytes from the input stream until a newline character is found. If the
 * InputStream does not contain anymore lines. Null is returned.
 */
public class WordListGuessProvider extends GuessProvider {

    private final BufferedReader bufferedReader;

    /**
     * Constructor
     *
     * @param stream
     *               An Input stream to read Guesses from
     */
    public WordListGuessProvider(InputStream stream) {
        super(GuessProviderType.WORDLIST);
        bufferedReader = new BufferedReader(new InputStreamReader(stream));
    }

    /**
     * Returns the next word from the input stream. If no more words are in the in InputStream null is returned.
     *
     * @return The next word from the input stream. If no more words are in the in InputStream null is returned.
     */
    @Override
    public byte[] getGuess() {
        try {
            String line = bufferedReader.readLine();
            if (line == null) {
                return null;
            }
            return ArrayConverter.hexStringToByteArray(line);
        } catch (IOException ex) {
            return null;
        }
    }
}
