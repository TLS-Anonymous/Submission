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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.DynamicValueConstraints;
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
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.model.ModelType;
import anonymous.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
@Tag("tls12")
@TlsVersion(supported = ProtocolVersion.TLS12)
@KeyExchange(supported = KeyExchangeType.ALL12, requiresServerKeyExchMsg = true)
public class ServerKeyExchange extends TlsGenericTest {

    @TlsTest(description = "Send a Server Key Exchange Message with a modified length value (-1)")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void serverKeyExchangeLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        ServerKeyExchangeMessage serverKeyExchange = (ServerKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
        serverKeyExchange.setLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
    
    @TlsTest(description = "Send a Server Key Exchange Message with a modified signature length value (-1)")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @DynamicValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isNotAnonymousCipherSuite")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void serverKeyExchangeSignatureLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        ServerKeyExchangeMessage serverKeyExchange = (ServerKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
        serverKeyExchange.setSignatureLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
    
    @TlsTest(description = "Send a Server Key Exchange Message with a modified public key length value (-1)")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void serverKeyExchangePublicKeyLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        ServerKeyExchangeMessage serverKeyExchange = (ServerKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
        serverKeyExchange.setPublicKeyLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
    
    @TlsTest(description = "Send a Diffie-Hellman Server Key Exchange Message with a modified modulus length value (-1)")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void modulusLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        DHEServerKeyExchangeMessage serverKeyExchange = (DHEServerKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
        serverKeyExchange.setModulusLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
    
    @TlsTest(description = "Send a Diffie-Hellman Server Key Exchange Message with a modified generator length value (-1)")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void generatorLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        DHEServerKeyExchangeMessage serverKeyExchange = (DHEServerKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, workflowTrace);
        serverKeyExchange.setGeneratorLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
    
    public boolean isNotAnonymousCipherSuite(CipherSuite cipherSuite) {
        return !cipherSuite.isAnon();
    }

}
