/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.CipherSuiteGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class CipherSuiteGuidelineCheck extends GuidelineCheck {

    /**
     * The protocol versions this check applies to.
     */
    private List<ProtocolVersion> versions;
    private List<CipherSuite> recommendedCipherSuites;

    private CipherSuiteGuidelineCheck() {
        super(null, null);
    }

    public CipherSuiteGuidelineCheck(String name, RequirementLevel requirementLevel, List<ProtocolVersion> versions,
        List<CipherSuite> recommendedCipherSuites) {
        super(name, requirementLevel);
        this.versions = versions;
        this.recommendedCipherSuites = recommendedCipherSuites;
    }

    public CipherSuiteGuidelineCheck(String name, RequirementLevel requirementLevel, GuidelineCheckCondition condition,
        List<ProtocolVersion> versions, List<CipherSuite> recommendedCipherSuites) {
        super(name, requirementLevel, condition);
        this.versions = versions;
        this.recommendedCipherSuites = recommendedCipherSuites;
    }

    @Override
    public GuidelineCheckResult evaluate(SiteReport report) {
        List<CipherSuite> nonRecommended = this.nonRecommendedSuites(report);
        return new CipherSuiteGuidelineCheckResult(TestResult.of(nonRecommended.isEmpty()), nonRecommended);
    }

    @Override
    public String getId() {
        return "CipherSuite_" + getRequirementLevel() + "_" + versions + "_" + recommendedCipherSuites;
    }

    private List<CipherSuite> nonRecommendedSuites(SiteReport report) {
        Set<CipherSuite> supported = new HashSet<>();
        for (VersionSuiteListPair pair : report.getVersionSuitePairs()) {
            if (versions.contains(pair.getVersion())) {
                supported.addAll(pair.getCipherSuiteList());
            }
        }
        return supported.stream().filter(suite -> !recommendedCipherSuites.contains(suite))
            .collect(Collectors.toList());
    }

    public List<ProtocolVersion> getVersions() {
        return versions;
    }

    public List<CipherSuite> getRecommendedCipherSuites() {
        return recommendedCipherSuites;
    }
}
