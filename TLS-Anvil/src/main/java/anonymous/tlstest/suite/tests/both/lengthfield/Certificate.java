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
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.KeyExchange;
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

@ClientTest
public class Certificate extends TlsGenericTest {
    
    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @TlsTest(description = "Send a Certificate Message with a modified length value (-1)")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void certificateMessageLengthTLS12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        certificateMessagLengthTest(workflowTrace, runner);
    }
    
    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @TlsTest(description = "Send a Certificate Message with a modified certificate list length value (-1)")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void certificateListLengthTLS12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        certificateListLengthTest(workflowTrace, runner);
    }
    
    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @TlsTest(description = "Send a Certificate Message with a modified length value (-1)")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void certificateMessageLengthTLS13(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(argumentAccessor, runner);
        certificateMessagLengthTest(workflowTrace, runner);
    }
    
    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13) 
    @TlsTest(description = "Send a Certificate Message with a modified certificate list length value (-1)")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void certificateListLengthTLS13(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(argumentAccessor, runner);
        certificateListLengthTest(workflowTrace, runner);
    }
    
    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @TlsTest(description = "Send a Certificate Message with a modified request context length value (+1)")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void certificateRequestContextLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(argumentAccessor, runner);
        CertificateMessage certificateMessage = (CertificateMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CERTIFICATE, workflowTrace);
        certificateMessage.setRequestContextLength(Modifiable.add(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
    
    
    private void certificateMessagLengthTest(WorkflowTrace workflowTrace, WorkflowRunner runner) {
        CertificateMessage certificateMessage = (CertificateMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CERTIFICATE, workflowTrace);
        certificateMessage.setLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest); 
    }
    
    private void certificateListLengthTest(WorkflowTrace workflowTrace, WorkflowRunner runner) {
        CertificateMessage certificateMessage = (CertificateMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CERTIFICATE, workflowTrace);
        certificateMessage.setCertificatesListLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
}
