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

public class NamedGroupOrderResult extends ProbeResult {

    private TestResult enforced;

    public NamedGroupOrderResult(TestResult enforced) {
        super(ProbeType.NAMED_GROUPS_ORDER);
        this.enforced = enforced;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.ENFORCES_NG_ORDERING, enforced);
    }
}
