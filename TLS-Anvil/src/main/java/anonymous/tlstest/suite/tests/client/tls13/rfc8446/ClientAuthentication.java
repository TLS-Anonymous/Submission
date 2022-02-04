/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.CertificateCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.InteroperabilityCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
@RFC(number = 8446, section = "4.4.2. Certificate")
public class ClientAuthentication extends Tls13Test {

    @TlsTest(description = "The client MUST send a Certificate message if and only if the server " +
            "has requested client authentication via a CertificateRequest message " +
            "(Section 4.3.2).[...] " +
            "If the server requests client authentication but no " +
            "suitable certificate is available, the client MUST send a " +
            "Certificate message containing no certificates [...] A Finished message MUST be sent regardless " +
            "of whether the Certificate message is empty.")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @CertificateCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @Tag("adjusted")
    public void clientSendsCertificateAndFinMessage(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setClientAuthentication(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilReceivingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CERTIFICATE_VERIFY);
        ((ReceiveAction)workflowTrace.getTlsActions().get(workflowTrace.getTlsActions().size() - 1)).getExpectedMessages().add(new FinishedMessage());
        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }
}
