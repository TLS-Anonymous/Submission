/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.server.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.KeyExchange;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ServerTest;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.CryptoCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.SecurityCategory;
import anonymous.tlstest.framework.constants.KeyExchangeType;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;


@RFC(number = 5246, section = "7.4.7.1")
@ServerTest
public class RSAEncryptedPremasterSecretMessage extends Tls12Test {

    @TlsTest(description = "Client implementations MUST always send the correct version number in PreMasterSecret. " +
            "If ClientHello.client_version is TLS 1.1 or higher, server implementations MUST check " +
            "the version number as described in the note below. [...]" +
            "In any case, a TLS server MUST NOT generate an alert if processing an " +
            "RSA-encrypted premaster secret message fails, or the version number " +
            "is not as expected.  Instead, it MUST continue the handshake with a " +
            "randomly generated premaster secret.")
    @KeyExchange(supported = KeyExchangeType.RSA)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @CryptoCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void PMWithWrongClientVersion(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);

        workflowTrace.addTlsActions(
                new SendAction(ActionOption.MAY_FAIL, new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        RSAClientKeyExchangeMessage cke = workflowTrace.getFirstSendMessage(RSAClientKeyExchangeMessage.class);
        cke.prepareComputations();
        //changes "0x03 0x03" to "0x03 0x02" (TLS1.2 to TLS1.1)
        cke.getComputations().setPremasterSecret(Modifiable.xor(new byte[] {0x00, 0x01}, 0));


        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "In any case, a TLS server MUST NOT generate an alert if processing an " +
            "RSA-encrypted premaster secret message fails, or the version number " +
            "is not as expected.  Instead, it MUST continue the handshake with a " +
            "randomly generated premaster secret.")
    @KeyExchange(supported = KeyExchangeType.RSA)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @CryptoCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void PMWithWrongPKCS1Padding(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);

        workflowTrace.addTlsActions(
                new SendAction(ActionOption.MAY_FAIL, new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        RSAClientKeyExchangeMessage cke = workflowTrace.getFirstSendMessage(RSAClientKeyExchangeMessage.class);
        cke.prepareComputations();
        //changes "0x00 0x02 random 0x00" to "0x00 0x03 random 0x00"
        cke.getComputations().setPlainPaddedPremasterSecret(Modifiable.xor(new byte[] {0x01}, 1));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

}
