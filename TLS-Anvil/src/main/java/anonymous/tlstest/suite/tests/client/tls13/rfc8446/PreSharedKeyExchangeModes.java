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
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
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
@RFC(number = 8446, section = "4.2.9 Pre-Shared Key Exchane Modes")
public class PreSharedKeyExchangeModes extends Tls13Test {

    public ConditionEvaluationResult supportsPSKModeExtension() {
        if (context.getReceivedClientHelloMessage().getExtension(PSKKeyExchangeModesExtensionMessage.class) != null) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("PSKModeExtension is not supported");
    }

    @TlsTest(description = "The server MUST NOT send a \"psk_key_exchange_modes\" extension.")
    @MethodCondition(method = "supportsPSKModeExtension")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void sendPSKModeExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddPSKKeyExchangeModesExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        ServerHelloMessage sh = workflowTrace.getFirstSendMessage(ServerHelloMessage.class);
        PSKKeyExchangeModesExtensionMessage ext = new PSKKeyExchangeModesExtensionMessage();
        ext.setExtensionBytes(Modifiable.explicit(context.getReceivedClientHelloMessage().getExtension(PSKKeyExchangeModesExtensionMessage.class).getExtensionBytes().getValue()));
        sh.addExtension(ext);

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

}
