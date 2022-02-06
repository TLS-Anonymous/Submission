/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.server.tls12.rfc6066;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.TestContext;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.MethodCondition;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ServerTest;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.InteroperabilityCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.testClasses.Tls12Test;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 6066, section = "4. Maximum Fragment Length Negotiation")
@ServerTest
public class MaximumFragmentLength extends Tls12Test {

    public ConditionEvaluationResult targetCanBeTested() {
        if(TestContext.getInstance().getSiteReport().getSupportedExtensions() != null &&
                TestContext.getInstance().getSiteReport().getSupportedExtensions().contains(ExtensionType.MAX_FRAGMENT_LENGTH)) {
            return ConditionEvaluationResult.enabled("The Extension can be tested");
        }
        return ConditionEvaluationResult.disabled("Target does not support the Extension");
    }
    
    @TlsTest(description = "If a server receives a maximum fragment length negotiation request for "+
            "a value other than the allowed values, it MUST abort the handshake with an \"illegal_parameter\" alert.")
    @HandshakeCategory(SeverityLevel.LOW)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @MethodCondition(method="targetCanBeTested")
    public void invalidMaximumFragmentLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddMaxFragmentLengthExtension(true);
        ClientHelloMessage chm = new ClientHelloMessage(c);

        chm.getExtension(MaxFragmentLengthExtensionMessage.class).setMaxFragmentLength(Modifiable.explicit(new byte[]{10}));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(chm),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            WorkflowTrace trace = i.getWorkflowTrace();
            AlertMessage alert = trace.getLastReceivedMessage(AlertMessage.class);

            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }
    
    @TlsTest(description = "Once a maximum fragment length other than 2^14 has been successfully " +
        "negotiated, the client and server MUST immediately begin fragmenting " +
        "messages (including handshake messages) to ensure that no fragment " +
        "larger than the negotiated length is sent.")
    @HandshakeCategory(SeverityLevel.LOW)
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @MethodCondition(method="targetCanBeTested")
    @Tag("new")
    public void respectsNegotiatedMaxFragmentLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddMaxFragmentLengthExtension(true);
        
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);
            ServerHelloMessage serverHello = i.getWorkflowTrace().getLastReceivedMessage(ServerHelloMessage.class);
            assertTrue("MaxFragmentLength has not been negotiated by the server", serverHello.containsExtension(ExtensionType.MAX_FRAGMENT_LENGTH));
            MaxFragmentLength selectedMaxFragment = MaxFragmentLength.getMaxFragmentLength(serverHello.getExtension(MaxFragmentLengthExtensionMessage.class).getMaxFragmentLength().getValue()[0]);
            int maxPlaintextFragmentSize = MaxFragmentLength.getIntegerRepresentation(selectedMaxFragment);

            WorkflowTrace trace = i.getWorkflowTrace();
            for(int j = 1; j < WorkflowTraceUtil.getAllReceivedRecords(trace).size(); j++) {
                Record record = (Record) WorkflowTraceUtil.getAllReceivedRecords(trace).get(j);
                assertTrue("Plaintextbytes of record exceeded limit", record.getCleanProtocolMessageBytes().getValue().length <= maxPlaintextFragmentSize);
            }
        });
    }

}
