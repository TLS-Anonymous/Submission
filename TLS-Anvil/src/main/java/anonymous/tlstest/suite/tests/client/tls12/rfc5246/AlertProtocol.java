/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.client.tls12.rfc5246;

import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.DynamicValueConstraints;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ScopeExtensions;
import anonymous.tlstest.framework.annotations.TlsTest;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.InteroperabilityCategory;
import anonymous.tlstest.framework.annotations.categories.SecurityCategory;
import anonymous.tlstest.framework.coffee4j.model.ModelFromScope;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.constants.TestResult;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.model.ModelType;
import anonymous.tlstest.framework.model.derivationParameter.AlertDerivation;
import anonymous.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 5246, section = "7.2.1 Closure Alerts")
@ClientTest
public class AlertProtocol extends Tls12Test {

    //alerts must not be fragmented
    public boolean recordLengthAllowsModification(Integer lengthCandidate) {
        return lengthCandidate >= 50;
    }

    @TlsTest(description = "Unless some other fatal alert has been transmitted, each party is "
            + "required to send a close_notify alert before closing the write side "
            + "of the connection. The other party MUST respond with a close_notify "
            + "alert of its own and close down the connection immediately, "
            + "discarding any pending writes.")
    @DynamicValueConstraints(affectedTypes = DerivationType.RECORD_LENGTH, methods = "recordLengthAllowsModification")
    @InteroperabilityCategory(SeverityLevel.LOW)
    @AlertCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.LOW)
    public void closeNotify(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.WARNING.getValue()));
        alert.setDescription(Modifiable.explicit(AlertDescription.CLOSE_NOTIFY.getValue()));

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HELLO, HandshakeMessageType.SERVER_HELLO_DONE);
        workflowTrace.getLastSendingAction().getSendMessages().add(alert);
        
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.smartExecutedAsPlanned(i);

            AlertMessage message = trace.getLastReceivedMessage(AlertMessage.class);
            if (message == null && Validator.socketClosed(i)) {
                i.addAdditionalResultInfo("No CLOSE NOTIFY Alert received.");
                i.setResult(TestResult.PARTIALLY_SUCCEEDED);
                return;
            }
            assertTrue("Socket has not been closed", Validator.socketClosed(i));
            Validator.receivedWarningAlert(i);
            Validator.testAlertDescription(i, AlertDescription.CLOSE_NOTIFY, message);

        });
    }

    @TlsTest(description = "Upon transmission or receipt of a fatal alert message, both " +
        "parties immediately close the connection.")
    @RFC(number = 5246, section = "7.2.2 Error Alerts")
    @ScopeExtensions(DerivationType.ALERT)
    @DynamicValueConstraints(affectedTypes = DerivationType.RECORD_LENGTH, methods = "recordLengthAllowsModification")
    @SecurityCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    public void abortAfterFatalAlertServerHello(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        AlertDescription description = derivationContainer.getDerivation(AlertDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit(description.getValue()));

        SendAction serverHelloAction = (SendAction) WorkflowTraceUtil.getFirstSendingActionForMessage(HandshakeMessageType.SERVER_HELLO, workflowTrace);
        serverHelloAction.getSendMessages().add(0, alert);

        runner.execute(workflowTrace, c).validateFinal(Validator::socketClosed);
    }

    @TlsTest(description = "Upon transmission or receipt of a fatal alert message, both " +
        "parties immediately close the connection.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @RFC(number = 5246, section = "7.2.2 Error Alerts")
    @SecurityCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @ScopeExtensions(DerivationType.ALERT)
    @DynamicValueConstraints(affectedTypes = DerivationType.RECORD_LENGTH, methods = "recordLengthAllowsModification")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    public void abortAfterFatalAlertServerHelloDone(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        AlertDescription description = derivationContainer.getDerivation(AlertDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit(description.getValue()));

        SendAction serverHelloAction = (SendAction) WorkflowTraceUtil.getFirstSendingActionForMessage(HandshakeMessageType.SERVER_HELLO, workflowTrace);
        serverHelloAction.getSendMessages().add(serverHelloAction.getSendMessages().size() - 1, alert);


        runner.execute(workflowTrace, c).validateFinal(Validator::socketClosed);
    }
}
