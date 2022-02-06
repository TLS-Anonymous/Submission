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
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.MethodCondition;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
@RFC(number = 8446, section = "4.3.1. Encrypted Extensions")
public class EncryptedExtensions extends Tls13Test {

    public ConditionEvaluationResult sentMaximumFragmentLength() {
        if (context.getReceivedClientHelloMessage().getExtension(MaxFragmentLengthExtensionMessage.class) != null) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Client does not support maximum fragment length");
    }

    private MaxFragmentLength getUnrequestedMaxFragLen(MaxFragmentLengthExtensionMessage req) {
        for (MaxFragmentLength len : MaxFragmentLength.values()) {
            if (req.getMaxFragmentLength().getValue()[0] != len.getValue()) {
                return len;
            }
        }
        return MaxFragmentLength.TWO_11;
    }

    @TlsTest(description = "The client MUST check EncryptedExtensions "
            + "for the presence of any forbidden extensions and if "
            + "any are found MUST abort the handshake "
            + "with an \"illegal_parameter\" alert.")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void sendSupportedVersionsExtensionInEE(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        EncryptedExtensionsMessage ee = workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class);
        ee.addExtension(new SupportedVersionsExtensionMessage());

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }

    @TlsTest(description = "The client MUST check EncryptedExtensions "
            + "for the presence of any forbidden extensions and if "
            + "any are found MUST abort the handshake "
            + "with an \"illegal_parameter\" alert.")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void sendPaddingExtensionInEE(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        EncryptedExtensionsMessage ee = workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class);
        ee.addExtension(new PaddingExtensionMessage());

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }

    @RFC(number = 6066, section = "4. Maximum Fragment Length Negotiation")
    @TlsTest(description = "Similarly, if a client receives a maximum fragment length negotiation "
            + "response that differs from the length it requested, it MUST also abort the handshake with an \"illegal_parameter\" alert.")
    @MethodCondition(method = "sentMaximumFragmentLength")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void invalidMaximumFragmentLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        EncryptedExtensionsMessage encExt = workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class);
        MaxFragmentLengthExtensionMessage malMaxFrag = new MaxFragmentLengthExtensionMessage();
        malMaxFrag.setMaxFragmentLength(Modifiable.explicit(new byte[]{5}));
        encExt.addExtension(malMaxFrag);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            WorkflowTrace wtrace = i.getWorkflowTrace();
            AlertMessage alert = wtrace.getLastReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }

    @RFC(number = 6066, section = "4. Maximum Fragment Length Negotiation")
    @TlsTest(description = "Similarly, if a client receives a maximum fragment length negotiation "
            + "response that differs from the length it requested, it MUST also abort the handshake with an \"illegal_parameter\" alert.")
    @MethodCondition(method = "sentMaximumFragmentLength")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void unrequestedMaximumFragmentLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        MaxFragmentLength unreqLen = getUnrequestedMaxFragLen(context.getReceivedClientHelloMessage().getExtension(MaxFragmentLengthExtensionMessage.class));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        EncryptedExtensionsMessage encExt = workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class);
        MaxFragmentLengthExtensionMessage malMaxFrag = new MaxFragmentLengthExtensionMessage();
        malMaxFrag.setMaxFragmentLength(Modifiable.explicit(new byte[]{unreqLen.getValue()}));
        encExt.addExtension(malMaxFrag);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            WorkflowTrace trace = i.getWorkflowTrace();
            AlertMessage alert = trace.getLastReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }
}
