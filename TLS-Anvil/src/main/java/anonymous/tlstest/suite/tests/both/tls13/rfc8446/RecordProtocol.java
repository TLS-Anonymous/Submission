/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.both.tls13.rfc8446;

import anonymous.tlstest.framework.annotations.DynamicValueConstraints;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ScopeExtensions;
import anonymous.tlstest.framework.annotations.ScopeLimitations;
import anonymous.tlstest.framework.annotations.TlsTest;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.InteroperabilityCategory;
import anonymous.tlstest.framework.annotations.categories.SecurityCategory;
import anonymous.tlstest.framework.coffee4j.model.ModelFromScope;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.constants.TestEndpointType;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.model.ModelType;
import anonymous.tlstest.framework.model.derivationParameter.ProtocolMessageTypeDerivation;
import anonymous.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import anonymous.tlstest.framework.annotations.categories.CryptoCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.RecordLayerCategory;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

@RFC(number = 8446, section = "5. Record Protocol")
public class RecordProtocol extends Tls13Test {

    @TlsTest(description = "Implementations MUST NOT send record types not "
            + "defined in this document unless negotiated by some extension. "
            + "If a TLS implementation receives an unexpected record type, "
            + "it MUST terminate the connection with an \"unexpected_message\" alert.")
    @RecordLayerCategory(SeverityLevel.LOW)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.LOW)
    public void invalidRecordContentType(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace;
        Record record = new Record();
        record.setContentType(Modifiable.explicit((byte) 0xff));
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            trace = new WorkflowTrace();
            trace.addTlsAction(new SendAction(new ClientHelloMessage(c)));
        } else {
            trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        }

        trace.addTlsAction(new ReceiveAction(new AlertMessage()));

        trace.getFirstAction(SendAction.class).setRecords(record);

        runner.execute(trace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.UNEXPECTED_MESSAGE, alert);
        });
    }

    @TlsTest(description = "Implementations MUST NOT send record types not "
            + "defined in this document unless negotiated by some extension. "
            + "If a TLS implementation receives an unexpected record type, "
            + "it MUST terminate the connection with an \"unexpected_message\" alert.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @RecordLayerCategory(SeverityLevel.LOW)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.LOW)
    public void invalidRecordContentTypeAfterEncryption(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        Record record = new Record();
        record.setContentType(Modifiable.explicit((byte) 0xff));
        FinishedMessage finished = new FinishedMessage(c);
        SendAction sendFinished = new SendAction(finished);
        sendFinished.setRecords(record);
        workflowTrace.addTlsActions(
                sendFinished,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.UNEXPECTED_MESSAGE, alert);
        });
    }

    @TlsTest(description = "If the decryption fails, the receiver MUST "
            + "terminate the connection with a \"bad_record_mac\" alert.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @ScopeExtensions(DerivationType.AUTH_TAG_BITMASK)
    @CryptoCategory(SeverityLevel.CRITICAL)
    @RecordLayerCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void invalidAuthTag(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] modificationBitmask = derivationContainer.buildBitmask();

        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setAuthenticationTag(Modifiable.xor(modificationBitmask, 0));

        SendAction appData = new SendAction(new ApplicationMessage());
        appData.setRecords(record);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        trace.addTlsActions(
                appData,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC, alert);
        });
    }

    @TlsTest(description = "The length (in bytes) of the following "
            + "TLSPlaintext.fragment.  The length MUST NOT exceed 2^14 bytes.  An "
            + "endpoint that receives a record that exceeds this length MUST "
            + "terminate the connection with a \"record_overflow\" alert. [...]"
            + "the full encoded TLSInnerPlaintext MUST NOT exceed 2^14 " 
            + "+ 1 octets.")
    //Note that the additional byte is the encoded content type, which we also add
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @RFC(number = 8446, section = "5.1. Record Layer and 5.4 Reccord Padding")
    @ScopeLimitations(DerivationType.RECORD_LENGTH)
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void sendRecordWithPlaintextOver2pow14(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.getDefaultClientConnection().setTimeout(2000);
        c.getDefaultServerConnection().setTimeout(2000);

        ApplicationMessage msg = new ApplicationMessage(c);
        Record overflowRecord = new Record();
        overflowRecord.setCleanProtocolMessageBytes(Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 1]));
        SendAction sendOverflow = new SendAction(msg);
        sendOverflow.setRecords(overflowRecord);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                sendOverflow,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.RECORD_OVERFLOW, alert);
        });
    }

    public boolean recordLengthAllowsModification(Integer lengthCandidate) {
        return lengthCandidate >= 50;
    }

    @TlsTest(description = "If the decryption fails, the receiver MUST "
            + "terminate the connection with a \"bad_record_mac\" alert.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @ScopeExtensions({DerivationType.CIPHERTEXT_BITMASK, DerivationType.APP_MSG_LENGHT})
    @DynamicValueConstraints(affectedTypes = DerivationType.RECORD_LENGTH, methods = "recordLengthAllowsModification")
    @RFC(number = 8446, section = "5.2. Record Payload Protection")
    @CryptoCategory(SeverityLevel.CRITICAL)
    @RecordLayerCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void invalidCiphertext(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] modificationBitmask = derivationContainer.buildBitmask();

        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setCiphertext(Modifiable.xor(modificationBitmask, 0));

        SendAction appData = new SendAction(new ApplicationMessage());
        appData.setRecords(record);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        trace.addTlsActions(
                appData,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC, alert);
        });
    }

    @TlsTest(description = "All encrypted TLS records can be padded to inflate the size of the "
            + "TLSCiphertext.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ScopeExtensions(DerivationType.ADDITIONAL_PADDING_LENGTH)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @RecordLayerCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void acceptsOptionalPadding(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);
        });
    }

    @TlsTest(description = "The length MUST NOT exceed 2^14 + 256 bytes. "
            + "An endpoint that receives a record that exceeds this "
            + "length MUST terminate the connection with a \"record_overflow\" alert. [...]"
            + "An endpoint that receives a record from its " 
            + "peer with TLSCiphertext.length larger than 2^14 + 256 octets MUST " 
            + "terminate the connection with a \"record_overflow\" alert.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ScopeLimitations(DerivationType.RECORD_LENGTH)
    @RFC(number = 8446, section = "5.2. Record Payload Protection")
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void sendRecordWithCiphertextOver2pow14plus256(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.getDefaultClientConnection().setTimeout(2000);
        c.getDefaultServerConnection().setTimeout(2000);

        Record overflowRecord = new Record();
        overflowRecord.setProtocolMessageBytes(Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 257]));
        //add dummy Application Message
        SendAction sendOverflow = new SendAction(new ApplicationMessage(c));
        sendOverflow.setRecords(overflowRecord);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                sendOverflow,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.RECORD_OVERFLOW, alert);
        });
    }

    @TlsTest(description = "Send a record without any content to increase the sequencenumber.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @RecordLayerCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @ScopeExtensions(DerivationType.PROTOCOL_MESSAGE_TYPE)
    @AlertCategory(SeverityLevel.LOW)
    @Tag("emptyRecord")
    public void sendEmptyRecord(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        ProtocolMessageType selectedRecordContentType = derivationContainer.getDerivation(ProtocolMessageTypeDerivation.class).getSelectedValue();
        ApplicationMessage appMsg = new ApplicationMessage(c);

        Record r = new Record();
        r.setContentType(Modifiable.explicit(selectedRecordContentType.getValue()));
        r.setProtocolMessageBytes(Modifiable.explicit(new byte[0]));
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(appMsg);
        sendAction.setRecords(r);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Zero-length "
            + "fragments of Application Data MAY be sent, as they are potentially "
            + "useful as a traffic analysis countermeasure.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @RecordLayerCategory(SeverityLevel.CRITICAL)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    public void sendZeroLengthApplicationRecord(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        ApplicationMessage appMsg = new ApplicationMessage(c);

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.APPLICATION_DATA);
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(appMsg);
        sendAction.setRecords(r);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                sendAction,
                new GenericReceiveAction()
        );

        runner.execute(workflowTrace, c).validateFinal(state -> {
            Validator.executedAsPlanned(state);
            AlertMessage msg = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            assertNull("Received alert message", msg);
            assertFalse("Socket was closed", Validator.socketClosed(state));
        });
    }
    
    @TlsTest(description = "Implementations MUST limit their scanning to the cleartext returned " +
        "from the AEAD decryption.  If a receiving implementation does not " +
        "find a non-zero octet in the cleartext, it MUST terminate the " +
        "connection with an \"unexpected_message\" alert.")
    @RFC(number = 8446, section = "5.4.  Record Padding")
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @RecordLayerCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void sendEncryptedHandshakeRecordWithNoNonZeroOctet(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        Record record = getRecordWithOnlyZeroOctets();
        
        WorkflowTrace trace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        trace.addTlsAction(new SendAction(new FinishedMessage(config)));
        trace.addTlsAction(new ReceiveAction(new AlertMessage()));
        //define modified record for finished
        ((SendAction)trace.getLastSendingAction()).setRecords(record);

        runner.execute(trace, config).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            Validator.testAlertDescription(i, AlertDescription.UNEXPECTED_MESSAGE);
        });
        
    }
    
    @TlsTest(description = "Implementations MUST limit their scanning to the cleartext returned " +
        "from the AEAD decryption.  If a receiving implementation does not " +
        "find a non-zero octet in the cleartext, it MUST terminate the " +
        "connection with an \"unexpected_message\" alert.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @RFC(number = 8446, section = "5.4.  Record Padding")
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @RecordLayerCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void sendEncryptedAppRecordWithNoNonZeroOctet(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        Record record = getRecordWithOnlyZeroOctets();
        
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        trace.addTlsAction(new SendAction(new ApplicationMessage(config)));
        trace.addTlsAction(new ReceiveAction(new AlertMessage()));
        //define modified record for finished
        ((SendAction)trace.getLastSendingAction()).setRecords(record);

        runner.execute(trace, config).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            Validator.testAlertDescription(i, AlertDescription.UNEXPECTED_MESSAGE);
        });
        
    }
    
    @TlsTest(description = "Implementations MUST NOT send any records with a version less than 0x0300.")
    @RFC(number = 8446, section = "D.5. Security Restrictions Related to Backward Compatibility")
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @RecordLayerCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void checkMinimumRecordProtocolVersions(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        runner.execute(workflowTrace, config).validateFinal(i -> {
            Validator.executedAsPlanned(i);
            testReceivedRecordVersions(i.getWorkflowTrace());
        });
    }

    private Record getRecordWithOnlyZeroOctets() {
        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setPlainRecordBytes(Modifiable.explicit(new byte[] {0x00, 0x00, 0x00, 0x00}));
        return record;
    }

    private void testReceivedRecordVersions(WorkflowTrace executedTrace) {
        for(ReceivingAction receiving: executedTrace.getReceivingActions()) {
            for(AbstractRecord abstractRecord : receiving.getReceivedRecords()) {
                if(abstractRecord instanceof Record) {
                    Record record = (Record) abstractRecord;
                    assertFalse("Peer sent a record with Protocol Version below 0x03 00", record.getProtocolVersion().getValue()[0] < 0x03);
                }
                
            }
        }
    }
}
