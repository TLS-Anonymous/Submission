/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class DtlsBugsResult extends ProbeResult {

    private TestResult isEarlyFinished;
    private TestResult isAcceptingUnencryptedAppData;
    private TestResult isAcceptingUnencryptedFinished;

    public DtlsBugsResult(TestResult isAcceptingUnencryptedFinished, TestResult isAcceptingUnencryptedAppData,
        TestResult isEarlyFinished) {
        super(ProbeType.DTLS_COMMON_BUGS);
        this.isAcceptingUnencryptedFinished = isAcceptingUnencryptedFinished;
        this.isAcceptingUnencryptedAppData = isAcceptingUnencryptedAppData;
        this.isEarlyFinished = isEarlyFinished;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.ACCEPTS_UNENCRYPTED_FINISHED, isAcceptingUnencryptedFinished);
        report.putResult(AnalyzedProperty.ACCEPTS_UNENCRYPTED_APP_DATA, isAcceptingUnencryptedAppData);
        report.putResult(AnalyzedProperty.HAS_EARLY_FINISHED_BUG, isEarlyFinished);
    }

}
