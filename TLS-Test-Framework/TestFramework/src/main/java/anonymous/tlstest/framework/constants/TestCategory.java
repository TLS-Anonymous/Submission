/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.constants;

import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.CVECategory;
import anonymous.tlstest.framework.annotations.categories.CertificateCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.CryptoCategory;
import anonymous.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.InteroperabilityCategory;
import anonymous.tlstest.framework.annotations.categories.MessageStructureCategory;
import anonymous.tlstest.framework.annotations.categories.RecordLayerCategory;
import anonymous.tlstest.framework.annotations.categories.SecurityCategory;

import java.lang.annotation.Annotation;

public enum TestCategory {
    ALERT(AlertCategory.class),
    CVE(CVECategory.class),
    CERTIFICATE(CertificateCategory.class),
    CRYPTO(CryptoCategory.class),
    DEPRECATED(DeprecatedFeatureCategory.class),
    HANDSHAKE(HandshakeCategory.class),
    MESSAGESTRUCTURE(MessageStructureCategory.class),
    RECORDLAYER(RecordLayerCategory.class),
    INTEROPERABILITY(InteroperabilityCategory.class),
    COMPLIANCE(ComplianceCategory.class),
    SECURITY(SecurityCategory.class);

    private final Class<? extends Annotation> annoationClass;

    TestCategory(Class<? extends Annotation> annotationClass) {
        this.annoationClass = annotationClass;
    }

    public Class<? extends Annotation> getAnnoationClass() {
        return annoationClass;
    }
}
