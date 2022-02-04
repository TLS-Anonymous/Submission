/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.server.tls12.rfc7685;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.EnforcedSenderRestriction;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ScopeLimitations;
import anonymous.tlstest.framework.annotations.ServerTest;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.testClasses.Tls12Test;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.assertFalse;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 7685, section = "3")
@ServerTest
public class PaddingExtension extends Tls12Test {
    private static final Logger LOGGER = LogManager.getLogger();


    @TlsTest(description = "The client MUST fill the padding extension completely with zero " +
            "bytes, although the padding extension_data field may be empty.")
    @ComplianceCategory(SeverityLevel.LOW)
    @HandshakeCategory(SeverityLevel.LOW) 
    @AlertCategory(SeverityLevel.LOW)
    @ScopeLimitations(DerivationType.INCLUDE_PADDING_EXTENSION)
    @EnforcedSenderRestriction
    public void paddingWithNonZero(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        config.setAddPaddingExtension(true);
        config.setDefaultPaddingExtensionBytes(new byte[]{(byte) 0xBA, (byte) 0xBE});

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(config)),
                new ReceiveAction(new AlertMessage(config))
        );

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
    
    @TlsTest(description = "The server MUST NOT echo the extension.")
    @ComplianceCategory(SeverityLevel.LOW)
    @HandshakeCategory(SeverityLevel.LOW) 
    @ScopeLimitations(DerivationType.INCLUDE_PADDING_EXTENSION)
    @Tag("new")
    public void serverDoesNotEcho(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        config.setAddPaddingExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(workflowTrace, config).validateFinal(i -> {
            Validator.executedAsPlanned(i);
            ServerHelloMessage serverHello = i.getWorkflowTrace().getFirstReceivedMessage(ServerHelloMessage.class);
            if(serverHello.getExtensions() != null) {
                assertFalse("Server responded with Padding Extension", serverHello.containsExtension(ExtensionType.PADDING));
            }
        });
    }
}
