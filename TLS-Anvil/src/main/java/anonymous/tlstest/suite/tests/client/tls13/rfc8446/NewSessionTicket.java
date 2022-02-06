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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.InteroperabilityCategory;
import anonymous.tlstest.framework.coffee4j.model.ModelFromScope;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.ModelType;
import anonymous.tlstest.framework.testClasses.Tls13Test;
import static org.junit.Assert.assertFalse;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
@RFC(number = 8446, section = "4.6.1. New Session Ticket Message")
public class NewSessionTicket extends Tls13Test {
    
    @TlsTest(description = "A set of extension values for the ticket.  The \"Extension\" format is defined in Section 4.2.  Clients MUST ignore unrecognized extensions. [...]"
            + "In TLS 1.3, a client receiving a CertificateRequest or NewSessionTicket MUST also ignore all unrecognized extensions.")
    @RFC(number = 8446, section = "4.6.1. New Session Ticket Message and 9.3. Protocol Invariants")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void ignoresUnknownNewSessionTicketExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(new SendAction(new NewSessionTicketMessage(c)));

        //we use a GREASE extension and overwrite its type
        //there are separate tests with GREASE groups 
        GreaseExtensionMessage unknownExtension = new GreaseExtensionMessage(ExtensionType.GREASE_00, 25);
        unknownExtension.setExtensionType(Modifiable.explicit(new byte[] {0x44, 0x23}));
        
        NewSessionTicketMessage msg = workflowTrace.getFirstSendMessage(NewSessionTicketMessage.class);
        msg.addExtension(unknownExtension);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);
            assertFalse("The connection was closed upon receiving the NewSessionTicket message", Validator.socketClosed(i));
        });
    }
}
