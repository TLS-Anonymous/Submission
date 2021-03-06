/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.serialization;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.Guideline;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineIO;
import de.rub.nds.tlsscanner.serverscanner.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.AnalyzedPropertyGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CipherSuiteGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.ExtensionGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.HashAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.KeySizeCertGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.NamedGroupsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAndHashAlgorithmsCertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAndHashAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import org.junit.Test;

import javax.xml.bind.JAXBException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class BsiGuidelineSerialization {

    @Test
    public void serialize() throws JAXBException {
        List<GuidelineCheck> checks = new ArrayList<>();

        checks.add(new AnalyzedPropertyGuidelineCheck("Grunds??tzlich werden TLS 1.2 und TLS 1.3 empfohlen.",
            RequirementLevel.MAY, AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE));
        checks.add(new AnalyzedPropertyGuidelineCheck("Grunds??tzlich werden TLS 1.2 und TLS 1.3 empfohlen.",
            RequirementLevel.MAY, AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE));
        checks.add(new AnalyzedPropertyGuidelineCheck("TLS 1.0 und TLS 1.1 werden nicht empfohlen.",
            RequirementLevel.SHOULD, AnalyzedProperty.SUPPORTS_TLS_1_0, TestResult.FALSE));
        checks.add(new AnalyzedPropertyGuidelineCheck("TLS 1.0 und TLS 1.1 werden nicht empfohlen.",
            RequirementLevel.SHOULD, AnalyzedProperty.SUPPORTS_TLS_1_1, TestResult.FALSE));
        checks.add(new AnalyzedPropertyGuidelineCheck("SSL v2 und SSL v3 werden nicht empfohlen.",
            RequirementLevel.SHOULD, AnalyzedProperty.SUPPORTS_SSL_2, TestResult.FALSE));
        checks.add(new AnalyzedPropertyGuidelineCheck("SSL v2 und SSL v3 werden nicht empfohlen.",
            RequirementLevel.SHOULD, AnalyzedProperty.SUPPORTS_SSL_3, TestResult.FALSE));
        checks.add(new CipherSuiteGuidelineCheck(
            "Grunds??tzlich wird empfohlen, nur Cipher-Suiten einzusetzen, die die Anforderungen an die Algorithmen und Schl??ssell??ngen der [TR-02102-1] erf??llen.",
            RequirementLevel.SHOULD, Collections.singletonList(ProtocolVersion.TLS12),
            Arrays.asList(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM,

                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
                CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384,

                CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
                // CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
                // CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
                // CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256,
                CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
                CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM, CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM,
                CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
                CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384)));
        checks.add(new NamedGroupsGuidelineCheck("Die folgenden Diffie-Hellman Gruppen werden empfohlen.",
            RequirementLevel.SHOULD,
            Arrays.asList(NamedGroup.SECP256R1, NamedGroup.SECP384R1, NamedGroup.BRAINPOOLP256R1,
                NamedGroup.BRAINPOOLP384R1, NamedGroup.BRAINPOOLP512R1, NamedGroup.FFDHE2048, NamedGroup.FFDHE3072,
                NamedGroup.FFDHE4096),
            Collections.emptyList(), false, 2));
        checks.add(new SignatureAlgorithmsGuidelineCheck("Die folgenden Signaturverfahren werden empfohlen.",
            RequirementLevel.SHOULD, new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE),
            Arrays.asList(SignatureAlgorithm.RSA, SignatureAlgorithm.DSA, SignatureAlgorithm.ECDSA)));
        checks.add(new HashAlgorithmsGuidelineCheck("Die folgenden Hashfunktionen werden empfohlen.",
            RequirementLevel.SHOULD, new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE),
            Arrays.asList(HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512)));
        checks.add(new AnalyzedPropertyGuidelineCheck(
            "Es wird empfohlen Session Renegotiation nur auf Basis von [RFC5746] zu verwenden. Durch den Client initiierte Renegotiation sollte vom Server abgelehnt werden.",
            RequirementLevel.SHOULD, new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE),
            AnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION, TestResult.TRUE));
        checks.add(new AnalyzedPropertyGuidelineCheck(
            "Es wird empfohlen Session Renegotiation nur auf Basis von [RFC5746] zu verwenden. Durch den Client initiierte Renegotiation sollte vom Server abgelehnt werden.",
            RequirementLevel.SHOULD, new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE),
            AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_EXTENSION, TestResult.FALSE));
        checks.add(new AnalyzedPropertyGuidelineCheck(
            "Es wird empfohlen Session Renegotiation nur auf Basis von [RFC5746] zu verwenden. Durch den Client initiierte Renegotiation sollte vom Server abgelehnt werden.",
            RequirementLevel.SHOULD, new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE),
            AnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION, TestResult.FALSE));
        checks.add(
            new ExtensionGuidelineCheck("truncated_hmac sollte nicht unterst??zt werden.", RequirementLevel.SHOULD_NOT,
                new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE),
                ExtensionType.TRUNCATED_HMAC));
        checks.add(new AnalyzedPropertyGuidelineCheck("Es wird empfohlen die TLS-Datenkompression nicht zu verwenden.",
            RequirementLevel.SHOULD, new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE),
            AnalyzedProperty.SUPPORTS_TLS_COMPRESSION, TestResult.FALSE));
        checks.add(new AnalyzedPropertyGuidelineCheck(
            "Der Einsatz der TLS-Erweiterung ???Encrypt-then-MAC??? gem???? [RFC7366] wird empfohlen.",
            RequirementLevel.SHOULD, new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE),
            AnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC, TestResult.TRUE));
        checks.add(new ExtensionGuidelineCheck("Heartbeat sollte nicht unterst??zt werden.", RequirementLevel.SHOULD_NOT,
            new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE), ExtensionType.HEARTBEAT));
        checks.add(new AnalyzedPropertyGuidelineCheck(
            "Der Einsatz der TLS-Erweiterung Extended Master Secret gem???? [RFC7627] wird empfohlen.",
            RequirementLevel.SHOULD, new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE),
            AnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET, TestResult.TRUE));
        checks.add(new AnalyzedPropertyGuidelineCheck("Das Senden oder Annehmen von 0-RTT Daten wird nicht empfohlen.",
            RequirementLevel.SHOULD, new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE),
            AnalyzedProperty.SUPPORTS_TLS13_0_RTT, TestResult.FALSE));
        checks.add(new NamedGroupsGuidelineCheck("Die folgenden Diffie-Hellman Gruppen werden empfohlen.",
            RequirementLevel.SHOULD, Arrays.asList(NamedGroup.SECP256R1, NamedGroup.SECP384R1,
                // NamedGroup.BRAINPOOLP256R1TLS13,
                // NamedGroup.BRAINPOOLP384R1TLS13,
                // NamedGroup.BRAINPOOLP512R1TLS13,
                NamedGroup.FFDHE2048, NamedGroup.FFDHE3072, NamedGroup.FFDHE4096),
            Collections.emptyList(), true, 2));
        checks.add(new SignatureAndHashAlgorithmsGuidelineCheck("Die folgenden Signaturverfahren werden empfohlen.",
            RequirementLevel.SHOULD, new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE),
            Arrays.asList(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256, SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384,
                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512, SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA256,
                SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA384, SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA512,
                SignatureAndHashAlgorithm.ECDSA_SHA256, SignatureAndHashAlgorithm.ECDSA_SHA384
            // SignatureAndHashAlgorithm.ECDSA_BRAINPOOLP256R1TLS13_SHA256,
            // SignatureAndHashAlgorithm.ECDSA_BRAINPOOLP384R1TLS13_SHA384,
            // SignatureAndHashAlgorithm.ECDSA_BRAINPOOLP512R1TLS13_SHA512
            ), true));
        checks.add(new SignatureAndHashAlgorithmsCertificateGuidelineCheck(
            "Die folgenden Signaturverfahren werden empfohlen.", RequirementLevel.SHOULD,
            new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE),
            Arrays.asList(SignatureAndHashAlgorithm.RSA_SHA256, SignatureAndHashAlgorithm.RSA_SHA384,
                SignatureAndHashAlgorithm.RSA_SHA512, SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256,
                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384, SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512,
                SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA256, SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA384,
                SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA512, SignatureAndHashAlgorithm.ECDSA_SHA256,
                SignatureAndHashAlgorithm.ECDSA_SHA384
            // SignatureAndHashAlgorithm.ECDSA_BRAINPOOLP256R1TLS13_SHA256,
            // SignatureAndHashAlgorithm.ECDSA_BRAINPOOLP384R1TLS13_SHA384,
            // SignatureAndHashAlgorithm.ECDSA_BRAINPOOLP512R1TLS13_SHA512
            )));
        checks
            .add(new CipherSuiteGuidelineCheck("Die folgenden Cipher-Suiten werden empfohlen.", RequirementLevel.SHOULD,
                Collections.singletonList(ProtocolVersion.TLS13), Arrays.asList(CipherSuite.TLS_AES_128_GCM_SHA256,
                    CipherSuite.TLS_AES_256_GCM_SHA384, CipherSuite.TLS_AES_128_CCM_SHA256)));
        checks.add(new KeySizeCertGuidelineCheck("Schl??ssell??ngen", RequirementLevel.SHOULD, 2000, 2000, 250, 2000));

        Guideline guideline = new Guideline("BSI TR-02102-2",
            "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102-2.html",
            checks);
        GuidelineIO.writeGuideline(guideline, Paths.get("src/main/resources/guideline/bsi.xml"));
    }
}
