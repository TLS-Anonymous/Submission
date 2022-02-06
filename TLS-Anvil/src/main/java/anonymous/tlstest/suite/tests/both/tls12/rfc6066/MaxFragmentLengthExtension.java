/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.both.tls12.rfc6066;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.MethodCondition;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ScopeLimitations;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.constants.TestEndpointType;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 6066, section = "4.  Maximum Fragment Length Negotiation")
public class MaxFragmentLengthExtension extends Tls12Test {
    
    public ConditionEvaluationResult supportsMaxFragmentLength() {
        if ((context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER && context.getSiteReport().getSupportedExtensions().contains(ExtensionType.MAX_FRAGMENT_LENGTH)) ||
                (context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT && context.getReceivedClientHelloMessage().containsExtension(ExtensionType.MAX_FRAGMENT_LENGTH))) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Client does not support maximum fragment length");
    }
    
    @TlsTest(description = "Note that the " +
        "output of the record layer may be larger.  For example, if the " +
        "negotiated length is 2^9=512, then, when using currently defined " +
        "cipher suites (those defined in [RFC5246] and [RFC2712]) and null " +
        "compression, the record-layer output can be at most 805 bytes: 5 " +
        "bytes of headers, 512 bytes of application data, 256 bytes of " +
        "padding, and 32 bytes of MAC.  This means that in this event a TLS " +
        "record-layer peer receiving a TLS record-layer message larger than " +
        "805 bytes MUST discard the message and send a \"record_overflow\" " +
        "alert, without decrypting the message.")
    @HandshakeCategory(SeverityLevel.LOW)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @ScopeLimitations(DerivationType.MAX_FRAGMENT_LENGTH)
    @MethodCondition(method="supportsMaxFragmentLength")
    @Tag("new")
    public void enforcesRecordLimit(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setDefaultMaxFragmentLength(MaxFragmentLength.TWO_9);
        config.setAddMaxFragmentLengthExtension(true);
        MaxFragmentLength maxLength = getNegotiatedMaxFragmentLength(config); 
        ApplicationMessage overflowingAppData = new ApplicationMessage(config);
        overflowingAppData.setData(Modifiable.explicit(new byte[MaxFragmentLength.getIntegerRepresentation(maxLength) + 256 + 32]));
        
        SendAction sendOverflowingRecord = new SendAction(overflowingAppData);
        
        //use a record that ignores the extension's limitations
        Record fullRecord = new Record();
        fullRecord.setMaxRecordLengthConfig(16384);
        sendOverflowingRecord.setRecords(fullRecord);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsAction(sendOverflowingRecord);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        
        runner.execute(workflowTrace, config).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            Validator.testAlertDescription(i, AlertDescription.RECORD_OVERFLOW);
        });
    }
    
    private MaxFragmentLength getNegotiatedMaxFragmentLength(Config config) {
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            return config.getDefaultMaxFragmentLength();
        } else {
            return MaxFragmentLength.getMaxFragmentLength(context.getReceivedClientHelloMessage().getExtension(MaxFragmentLengthExtensionMessage.class).getMaxFragmentLength().getValue()[0]);
        }
    }
}
