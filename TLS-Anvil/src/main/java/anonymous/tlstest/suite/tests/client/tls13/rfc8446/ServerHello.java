/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.KeyExchange;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ScopeLimitations;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.SecurityCategory;
import anonymous.tlstest.framework.coffee4j.model.ModelFromScope;
import anonymous.tlstest.framework.constants.KeyExchangeType;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.model.ModelType;
import anonymous.tlstest.framework.testClasses.Tls13Test;

import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.util.Random;

@RFC(number = 8446, section = "4.1.3 Server Hello")
@ClientTest
public class ServerHello extends Tls13Test {

    @TlsTest(description = "A client which receives a legacy_session_id_echo "
            + "field that does not match what it sent in the ClientHello MUST "
            + "abort the handshake with an \"illegal_parameter\" alert.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void testSessionId(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );
        sharedSessionIdTest(workflowTrace, runner);
    }

    public static void sharedSessionIdTest(WorkflowTrace workflowTrace, WorkflowRunner runner) {
        ServerHelloMessage sh = workflowTrace.getFirstSendMessage(ServerHelloMessage.class);
        
        //WolfSSL expects 32 bytes - to be determined if this is correct behavior
        byte[] dummySessionId = new byte[32];
        dummySessionId[0] = (byte) 0xFF;
        dummySessionId[16] = (byte) 0xFF;
        sh.setSessionId(Modifiable.explicit(dummySessionId));

        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            if(trace.getLastReceivedMessage(ClientHelloMessage.class) != null 
                    && trace.getLastReceivedMessage(ClientHelloMessage.class).getSessionIdLength().getValue() == 0) {
                i.addAdditionalResultInfo("Client did not set SessionID");
            }
            Validator.receivedFatalAlert(i);

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, msg);
        });
    }

    @TlsTest(description = "A client which receives a cipher suite that was "
            + "not offered MUST abort the handshake with "
            + "an \"illegal_parameter\" alert.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ScopeLimitations(DerivationType.CIPHERSUITE)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void testCipherSuite(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        ServerHelloMessage sh = workflowTrace.getFirstSendMessage(ServerHelloMessage.class);
        sh.setSelectedCipherSuite(Modifiable.explicit(CipherSuite.GREASE_00.getByteValue()));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);
        });
    }

    @TlsTest(description = "legacy_compression_method: A single byte which "
            + "MUST have the value 0.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @DeprecatedFeatureCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void testCompressionValue(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );
        sharedCompressionValueTest(workflowTrace, runner);
    }

    public static void sharedCompressionValueTest(WorkflowTrace workflowTrace, WorkflowRunner runner) {
        ServerHelloMessage sh = workflowTrace.getFirstSendMessage(ServerHelloMessage.class);
        sh.setSelectedCompressionMethod(Modifiable.explicit((byte) 0x01));

        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);
        });
    }

    @TlsTest(description = "TLS 1.3 clients receiving a ServerHello indicating TLS 1.2 or below " +
        "MUST check that the last 8 bytes are not equal to either of these " +
        "values. [...] If a match is found, the client MUST abort the handshake with " +
        "an \"illegal_parameter\" alert.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.CRITICAL)
    public void testRandomDowngradeValue(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);

        Random random = new Random();
        byte[] serverRandom = new byte[32];
        random.nextBytes(serverRandom);

        byte[] downgradeValue = new byte[]{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01};
        System.arraycopy(downgradeValue, 0, serverRandom, 24, downgradeValue.length);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.SERVER_HELLO_DONE);
        workflowTrace.addTlsActions(
                new SendAction(ActionOption.MAY_FAIL, new ServerHelloDoneMessage()),
                new ReceiveAction(new AlertMessage())
        );

        workflowTrace.getFirstSendMessage(ServerHelloMessage.class).setRandom(Modifiable.explicit(serverRandom));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, msg);
        });
    }
}
