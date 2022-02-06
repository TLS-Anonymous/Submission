/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.server.both.statemachine;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.execution.WorkflowRunner;

/**
 * Provides test and evaluation functionalities for both TLS 1.2 and 1.3
 * server state machines
 */
public class SharedStateMachineTest {
    
    public static void sharedBeginWithApplicationDataTest(Config config, WorkflowRunner runner) {
        runner.setPreparedConfig(config);
        config.setDefaultApplicationMessageData("Test");
        WorkflowTrace workflowTrace = new WorkflowTrace();
        ApplicationMessage applicationMessage = new ApplicationMessage(config);
        workflowTrace.addTlsAction(new SendAction(applicationMessage));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
    
    public static void sharedBeginWithChangeCipherSpecTest(Config config, WorkflowRunner runner) {
       runner.setPreparedConfig(config);
       WorkflowTrace workflowTrace = new WorkflowTrace();
       workflowTrace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
       workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
       runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert); 
    }
    
    public static void sharedBeginWithFinishedTest(Config config, WorkflowRunner runner) {
        runner.setPreparedConfig(config);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new SendAction(new FinishedMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
    
    public static void sharedSecondClientHelloAfterServerHelloTest(Config config, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
    
    public static void sharedSecondClientHelloTest(Config config, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        ClientHelloMessage additionalClientHello = new ClientHelloMessage(config);
        additionalClientHello.setIncludeInDigest(Modifiable.explicit(false));
        additionalClientHello.setAdjustContext(Modifiable.explicit(false));
        SendAction initialSendAction = (SendAction) workflowTrace.getFirstSendingAction();
        initialSendAction.getMessages().add(additionalClientHello);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
}
