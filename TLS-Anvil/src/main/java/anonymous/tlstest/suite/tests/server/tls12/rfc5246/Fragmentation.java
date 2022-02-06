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
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.EnforcedSenderRestriction;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ScopeLimitations;
import anonymous.tlstest.framework.annotations.ServerTest;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.InteroperabilityCategory;
import anonymous.tlstest.framework.annotations.categories.RecordLayerCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 5246, section = "6.2.1 Fragmentation")
@ServerTest
public class Fragmentation extends Tls12Test {

    @TlsTest(description = "Implementations MUST NOT send zero-length fragments of Handshake, "
            + "Alert, or ChangeCipherSpec content types. Zero-length fragments of "
            + "Application data MAY be sent as they are potentially useful as a "
            + "traffic analysis countermeasure.")
    @ScopeLimitations(DerivationType.RECORD_LENGTH)
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    @EnforcedSenderRestriction
    public void sendZeroLengthRecord_CH(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setUseAllProvidedRecords(true);

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        r.setMaxRecordLengthConfig(0);
        ClientHelloMessage cHello = new ClientHelloMessage(c);
        cHello.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        SendAction sendAction = new SendAction(cHello);
        sendAction.setRecords(r);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Implementations MUST NOT send zero-length fragments of Handshake, "
            + "Alert, or ChangeCipherSpec content types. Zero-length fragments of "
            + "Application data MAY be sent as they are potentially useful as a "
            + "traffic analysis countermeasure.")
    @ScopeLimitations(DerivationType.RECORD_LENGTH)
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    @EnforcedSenderRestriction
    public void sendZeroLengthRecord_Alert(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setUseAllProvidedRecords(true);

        AlertMessage alertMsg = new AlertMessage(c);
        alertMsg.setLevel(Modifiable.explicit(AlertLevel.WARNING.getValue()));
        alertMsg.setDescription(Modifiable.explicit(AlertDescription.CLOSE_NOTIFY.getValue()));

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.ALERT);
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(alertMsg);
        sendAction.setRecords(r);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HELLO, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Client " +
        "message boundaries are not preserved in the record layer (i.e., " +
        "multiple client messages of the same ContentType MAY be coalesced " +
        "into a single TLSPlaintext record, or a single message MAY be " +
        "fragmented across several records).")
    @ScopeLimitations({DerivationType.RECORD_LENGTH, DerivationType.TCP_FRAGMENTATION})
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void sendHandshakeMessagesWithinMultipleRecords_CKE_CCS_F(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        if (c.isClientAuthentication()) {
            workflowTrace.addTlsActions(new SendAction(new CertificateMessage(c)));
        }
        workflowTrace.addTlsActions(new SendDynamicClientKeyExchangeAction());

        if (c.isClientAuthentication()) {
            workflowTrace.addTlsActions(new SendAction(new CertificateVerifyMessage(c)));
        }

        workflowTrace.addTlsActions(new SendAction(new ChangeCipherSpecMessage(c)));
        workflowTrace.addTlsActions(new SendAction(new FinishedMessage(c)));
        workflowTrace.addTlsActions(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

    @TlsTest(description = "Client " +
        "message boundaries are not preserved in the record layer (i.e., " +
        "multiple client messages of the same ContentType MAY be coalesced " +
        "into a single TLSPlaintext record, or a single message MAY be " +
        "fragmented across several records).")
    @ScopeLimitations({DerivationType.RECORD_LENGTH, DerivationType.TCP_FRAGMENTATION})
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void sendHandshakeMessagesWithinMultipleRecords_CKE_CCSF(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.getDefaultClientConnection().setTransportHandlerType(TransportHandlerType.TCP_NO_DELAY);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        if (c.isClientAuthentication()) {
            workflowTrace.addTlsActions(new SendAction(new CertificateMessage(c)));
        }
        workflowTrace.addTlsActions(new SendDynamicClientKeyExchangeAction());

        if (c.isClientAuthentication()) {
            workflowTrace.addTlsActions(new SendAction(new CertificateVerifyMessage(c)));
        }

        workflowTrace.addTlsActions(new SendAction(new ChangeCipherSpecMessage(c), new FinishedMessage(c)));
        workflowTrace.addTlsActions(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

}
