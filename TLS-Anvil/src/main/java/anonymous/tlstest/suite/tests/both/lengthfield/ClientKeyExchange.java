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
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import anonymous.tlstest.framework.annotations.KeyExchange;
import anonymous.tlstest.framework.annotations.ServerTest;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.TlsVersion;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.MessageStructureCategory;
import anonymous.tlstest.framework.coffee4j.model.ModelFromScope;
import anonymous.tlstest.framework.constants.KeyExchangeType;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.ModelType;
import anonymous.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@Tag("tls12")
@TlsVersion(supported = ProtocolVersion.TLS12)
@KeyExchange(supported = KeyExchangeType.ALL12)
public class ClientKeyExchange extends TlsGenericTest {
    
    @TlsTest(description = "Send a Client Key Exchange Message with a modified length value (-1)")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void clientKeyExchangeLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getWorkflowTraceSeparatedClientKeyExchange(argumentAccessor, runner);
        ClientKeyExchangeMessage clientKeyExchange = (ClientKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE, workflowTrace);
        clientKeyExchange.setLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
    
    @TlsTest(description = "Send a Client Key Exchange Message with a modified public key length value (-1)")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void clientKeyExchangePublicKeyLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getWorkflowTraceSeparatedClientKeyExchange(argumentAccessor, runner);
        ClientKeyExchangeMessage clientKeyExchange = (ClientKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE, workflowTrace);
        clientKeyExchange.setPublicKeyLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
    
    
    private WorkflowTrace getWorkflowTraceSeparatedClientKeyExchange(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        SendAction sendCkeCcsFin = (SendAction) WorkflowTraceUtil.getFirstSendingActionForMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE, workflowTrace);
        ClientKeyExchangeMessage clientKeyExchange = (ClientKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE, workflowTrace);
        sendCkeCcsFin.getSendMessages().remove(clientKeyExchange);
        sendCkeCcsFin.addActionOption(ActionOption.MAY_FAIL);
        workflowTrace.getTlsActions().add(workflowTrace.getTlsActions().indexOf(sendCkeCcsFin), new SendAction(clientKeyExchange));
        return workflowTrace;
    }
}
