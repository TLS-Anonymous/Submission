/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.UnknownProtocolVersionException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;

public enum ProtocolVersion {

    SSL2(new byte[] { (byte) 0x00, (byte) 0x02 }),
    SSL3(new byte[] { (byte) 0x03, (byte) 0x00 }),
    TLS10(new byte[] { (byte) 0x03, (byte) 0x01 }),
    TLS11(new byte[] { (byte) 0x03, (byte) 0x02 }),
    TLS12(new byte[] { (byte) 0x03, (byte) 0x03 }),
    TLS13(new byte[] { (byte) 0x03, (byte) 0x04 }),
    TLS13_DRAFT14(new byte[] { (byte) 0x7F, (byte) 0x0E }),
    TLS13_DRAFT15(new byte[] { (byte) 0x7F, (byte) 0x0F }),
    TLS13_DRAFT16(new byte[] { (byte) 0x7F, (byte) 0x10 }),
    TLS13_DRAFT17(new byte[] { (byte) 0x7F, (byte) 0x11 }),
    TLS13_DRAFT18(new byte[] { (byte) 0x7F, (byte) 0x12 }),
    TLS13_DRAFT19(new byte[] { (byte) 0x7F, (byte) 0x13 }),
    TLS13_DRAFT20(new byte[] { (byte) 0x7F, (byte) 0x14 }),
    TLS13_DRAFT21(new byte[] { (byte) 0x7F, (byte) 0x15 }),
    TLS13_DRAFT22(new byte[] { (byte) 0x7F, (byte) 0x16 }),
    TLS13_DRAFT23(new byte[] { (byte) 0x7F, (byte) 0x17 }),
    TLS13_DRAFT24(new byte[] { (byte) 0x7F, (byte) 0x18 }),
    TLS13_DRAFT25(new byte[] { (byte) 0x7F, (byte) 0x19 }),
    TLS13_DRAFT26(new byte[] { (byte) 0x7F, (byte) 0x1A }),
    TLS13_DRAFT27(new byte[] { (byte) 0x7F, (byte) 0x1B }),
    TLS13_DRAFT28(new byte[] { (byte) 0x7F, (byte) 0x1C }),
    DTLS10(new byte[] { (byte) 0xFE, (byte) 0xFF }),
    DTLS12(new byte[] { (byte) 0xFE, (byte) 0xFD }),

    // GREASE constants
    GREASE_00(new byte[] { (byte) 0x0A, (byte) 0x0A }),
    GREASE_01(new byte[] { (byte) 0x1A, (byte) 0x1A }),
    GREASE_02(new byte[] { (byte) 0x2A, (byte) 0x2A }),
    GREASE_03(new byte[] { (byte) 0x3A, (byte) 0x3A }),
    GREASE_04(new byte[] { (byte) 0x4A, (byte) 0x4A }),
    GREASE_05(new byte[] { (byte) 0x5A, (byte) 0x5A }),
    GREASE_06(new byte[] { (byte) 0x6A, (byte) 0x6A }),
    GREASE_07(new byte[] { (byte) 0x7A, (byte) 0x7A }),
    GREASE_08(new byte[] { (byte) 0x8A, (byte) 0x8A }),
    GREASE_09(new byte[] { (byte) 0x9A, (byte) 0x9A }),
    GREASE_10(new byte[] { (byte) 0xAA, (byte) 0xAA }),
    GREASE_11(new byte[] { (byte) 0xBA, (byte) 0xBA }),
    GREASE_12(new byte[] { (byte) 0xCA, (byte) 0xCA }),
    GREASE_13(new byte[] { (byte) 0xDA, (byte) 0xDA }),
    GREASE_14(new byte[] { (byte) 0xEA, (byte) 0xEA }),
    GREASE_15(new byte[] { (byte) 0xFA, (byte) 0xFA });

    private byte[] value;

    private static final Map<Integer, ProtocolVersion> MAP;

    private ProtocolVersion(byte[] value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (ProtocolVersion c : ProtocolVersion.values()) {
            MAP.put(valueToInt(c.value), c);
        }
    }

    private static Integer valueToInt(byte[] value) {
        if (value.length == 2) {
            return (value[0] & 0xff) << Bits.IN_A_BYTE | (value[1] & 0xff);
        } else {
            return null;
        }
    }

    public boolean isDTLS() {
        return this == DTLS10 || this == DTLS12;
    }

    public static ProtocolVersion getProtocolVersion(byte[] value) {
        Integer i = valueToInt(value);
        if (i == null) {
            return null;
        }
        return MAP.get(i);
    }

    public static void sort(List<ProtocolVersion> versions) {
        sort(versions, true);
    }

    public static void sort(List<ProtocolVersion> versions, boolean ascending) {
        Comparator<ProtocolVersion> comparator = new ProtocolVersionComparator();
        if (!ascending) {
            comparator = comparator.reversed();
        }
        versions.sort(comparator);
    }

    public static List<ProtocolVersion> getProtocolVersions(byte[] values) {
        List<ProtocolVersion> versions = new LinkedList<>();
        if (values.length % 2 != 0) {
            throw new UnknownProtocolVersionException("Last ProtocolVersion are unknown!");
        }
        int pointer = 0;
        while (pointer < values.length) {
            byte[] version = new byte[2];
            version[0] = values[pointer];
            version[1] = values[pointer + 1];
            ProtocolVersion tempVersion = getProtocolVersion(version);
            if (tempVersion != null) {
                versions.add(tempVersion);
            }
            pointer += 2;
        }
        return versions;
    }

    public static ProtocolVersion getRandom(Random random) {
        ProtocolVersion c = null;
        while (c == null) {
            Object[] o = MAP.values().toArray();
            c = (ProtocolVersion) o[random.nextInt(o.length)];
        }
        return c;
    }

    public byte[] getValue() {
        return value;
    }

    public byte getMajor() {
        return value[0];
    }

    public byte getMinor() {
        return value[1];
    }

    /**
     * Maps a string protocol version value to an enum. It handles specific cases like TLSv1.2 or SSLv3
     *
     * @param  protocolVersion
     *                         The ProtocolVersion as a String
     * @return                 The ProtocolVersion as an Enum
     */
    public static ProtocolVersion fromString(String protocolVersion) {
        protocolVersion = protocolVersion.replaceFirst("v", "");
        protocolVersion = protocolVersion.replaceFirst("\\.", "");
        for (ProtocolVersion pv : ProtocolVersion.values()) {
            if (protocolVersion.equalsIgnoreCase(pv.toString())) {
                return pv;
            }
        }
        throw new IllegalArgumentException("Value " + protocolVersion + " cannot be converted to a protocol version. "
            + "Available values are: " + Arrays.toString(ProtocolVersion.values()));
    }

    /**
     * Return the highest protocol version.
     *
     * @param  list
     *              The List of protocolVersions to search in
     * @return      The highest ProtocolVersion
     */
    public static ProtocolVersion getHighestProtocolVersion(List<ProtocolVersion> list) {
        ProtocolVersion highestProtocolVersion = null;
        for (ProtocolVersion pv : list) {
            if (pv.isGrease())
                continue;
            if (highestProtocolVersion == null) {
                highestProtocolVersion = pv;
            }
            if (pv != null && ArrayConverter.bytesToInt(pv.getValue())
                > ArrayConverter.bytesToInt(highestProtocolVersion.getValue())) {
                highestProtocolVersion = pv;
            }
        }
        return highestProtocolVersion;
    }

    /**
     * Return true, if protocol version TLS 1.3
     *
     * @return True if protocolVersion is TLS.13 or a Draft of TLS 1.3
     */
    public boolean isTLS13() {
        return this == TLS13 || this.getMajor() == 0x7F;
    }

    /**
     * @return true, if protocol version SSL 2 or 3
     */
    public boolean isSSL() {
        return this == SSL2 || this == SSL3;
    }

    public boolean isGrease() {
        return this.name().startsWith("GREASE");
    }

    public boolean usesExplicitIv() {
        return this == ProtocolVersion.TLS11 || this == ProtocolVersion.TLS12 || this == ProtocolVersion.DTLS10
            || this == ProtocolVersion.DTLS12;
    }

    public int compare(ProtocolVersion o1) {
        if (o1 == this || (o1.isGrease() && this.isGrease())) {
            return 0;
        }

        if (this.isGrease())
            return -1;
        if (o1.isGrease())
            return 1;

        if (ArrayConverter.bytesToInt(this.getValue()) > ArrayConverter.bytesToInt(o1.getValue())) {
            return 1;
        }
        return -1;
    }
}
