/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

import java.util.List;

public class CompressionsResult extends ProbeResult {

    private List<CompressionMethod> compressions;

    public CompressionsResult(List<CompressionMethod> compressions) {
        super(ProbeType.COMPRESSIONS);
        this.compressions = compressions;
    }

    @Override
    public void mergeData(SiteReport report) {
        if (compressions != null) {
            report.setSupportedCompressionMethods(compressions);
            if (compressions.contains(CompressionMethod.LZS) || compressions.contains(CompressionMethod.DEFLATE)) {
                report.putResult(AnalyzedProperty.VULNERABLE_TO_CRIME, TestResult.TRUE);
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_COMPRESSION, TestResult.TRUE);
            } else {
                report.putResult(AnalyzedProperty.VULNERABLE_TO_CRIME, TestResult.FALSE);
                report.putResult(AnalyzedProperty.SUPPORTS_TLS_COMPRESSION, TestResult.FALSE);
            }
        } else {
            report.putResult(AnalyzedProperty.VULNERABLE_TO_CRIME, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.SUPPORTS_TLS_COMPRESSION, TestResult.COULD_NOT_TEST);
        }
    }

}
