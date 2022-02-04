/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.client.tls12.rfc5246;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.InteroperabilityCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertNotNull;

import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
@RFC(number = 5246, section = "7.4.6. Client Certificate")
public class ClientCertificateMessage extends Tls12Test {

    @TlsTest(description = "If the server has sent " +
        "a CertificateRequest message, the client MUST send the Certificate " +
        "message. [...]" + 
        "If no suitable certificate is available, the client MUST send a certificate message containing no certificates.")
    @RFC(number = 5246, section = "7.3. Handshake Protocol Overview and 7.4.6. Client Certificate")
    @ComplianceCategory(SeverityLevel.HIGH)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.HIGH)
    public void clientMustSendCertMsg(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setClientAuthentication(true);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            assertNotNull("Client didn't send CertificateMessage", i.getWorkflowTrace().getFirstReceivedMessage(CertificateMessage.class));
        });
    }

}
