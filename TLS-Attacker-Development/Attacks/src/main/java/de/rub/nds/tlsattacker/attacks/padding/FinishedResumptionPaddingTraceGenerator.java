/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.padding;

import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.attacks.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.util.LinkedList;

/**
 *
 */
public class FinishedResumptionPaddingTraceGenerator extends PaddingTraceGenerator {

    /**
     *
     * @param type
     */
    public FinishedResumptionPaddingTraceGenerator(PaddingRecordGeneratorType type) {
        super(type);
    }

    /**
     *
     * @param  config
     * @return
     */
    @Override
    public WorkflowTrace getPaddingOracleWorkflowTrace(Config config, PaddingVector vector) {
        WorkflowTrace trace = new WorkflowConfigurationFactory(config)
            .createWorkflowTrace(WorkflowTraceType.FULL_RESUMPTION, RunningModeType.CLIENT);
        SendAction sendAction = (SendAction) trace.getLastSendingAction();
        LinkedList<AbstractRecord> recordList = new LinkedList<>();
        recordList.add(new Record(config));
        recordList.add(vector.createRecord());
        sendAction.setRecords(recordList);
        trace.addTlsAction(new GenericReceiveAction());
        return trace;
    }
}
