/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.both.lengthfield;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.KeyExchange;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.TlsVersion;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.MessageStructureCategory;
import anonymous.tlstest.framework.coffee4j.model.ModelFromScope;
import anonymous.tlstest.framework.constants.KeyExchangeType;
import anonymous.tlstest.framework.constants.TestEndpointType;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.ModelType;
import anonymous.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class Finished extends TlsGenericTest {
    
    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @TlsTest(description = "Send a Finished Message with a modified length value (-1)")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void finishedLengthTLS12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        finishedLengthTest(workflowTrace, runner);
    }
    
    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @TlsTest(description = "Send a Finished Message with a modified length value (-1)")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void finishedLengthTLS13(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(argumentAccessor, runner);
        finishedLengthTest(workflowTrace, runner);
    }
    
    private void finishedLengthTest(WorkflowTrace workflowTrace, WorkflowRunner runner) {
       FinishedMessage finishedMessage = (FinishedMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.FINISHED, workflowTrace);
       finishedMessage.setLength(Modifiable.sub(1)); 
       if((runner.getPreparedConfig().getHighestProtocolVersion() != ProtocolVersion.TLS13 && context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT)
               || (runner.getPreparedConfig().getHighestProtocolVersion() == ProtocolVersion.TLS13 && context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER)) {
           workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
           runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(Validator::receivedFatalAlert);
       } else {
           runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
       }
    }
}
