/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework;

import anonymous.tlstest.framework.model.derivationParameter.TcpFragmentationDerivation;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.protocol.handler.AlertHandler;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.TlsMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.record.crypto.RecordDecryptor;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import anonymous.tlstest.framework.constants.AssertMsgs;
import anonymous.tlstest.framework.constants.TestEndpointType;
import anonymous.tlstest.framework.constants.TestResult;
import anonymous.tlstest.framework.execution.AnnotatedState;

import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

public class Validator {
    private static final Logger LOGGER = LogManager.getLogger();

    public static boolean socketClosed(AnnotatedState i) {
        SocketState socketState = i.getState().getTlsContext().getFinalSocketState();
        return (socketState == SocketState.SOCKET_EXCEPTION || socketState == SocketState.CLOSED || socketState == SocketState.IO_EXCEPTION);
    }

    public static void receivedFatalAlert(AnnotatedState i, boolean checkExecutedAsPlanned) {
        WorkflowTrace trace = i.getWorkflowTrace();

        if (checkExecutedAsPlanned) {
            try {
                Validator.smartExecutedAsPlanned(i);
            } catch (Throwable e) {
                if(traceFailedBeforeAlertAction(trace)) {
                    i.addAdditionalResultInfo(AssertMsgs.WorkflowNotExecutedBeforeAlert);
                } else {
                    ReceivingAction alertReceivingAction = (ReceivingAction) WorkflowTraceUtil.getFirstReceivingActionForMessage(ProtocolMessageType.ALERT, trace);
                    i.addAdditionalResultInfo("Workflow failed at Alert receiving action. Received: " + alertReceivingAction.getReceivedMessages().stream().map(ProtocolMessage::toCompactString).collect(Collectors.joining(",")));
                }
                throw e;
            }
        }

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        List<ProtocolMessage> receivedAlerts = WorkflowTraceUtil.getAllReceivedMessages(trace, ProtocolMessageType.ALERT);
        if(receivedAlerts.size() > 1) {
            i.addAdditionalResultInfo("Received multiple Alerts while waiting for Fatal Alert (" + 
                    receivedAlerts.stream().map(alert -> ((TlsMessage)alert).toCompactString()).collect(Collectors.joining(","))+ ")");
        }
        boolean socketClosed = socketClosed(i);
        if (msg == null && socketClosed) {
            if(i.getState().getConfig().getHighestProtocolVersion() == ProtocolVersion.TLS13 && !TestContext.getInstance().getConfig().isExpectTls13Alerts()) {
                i.addAdditionalResultInfo("SUT chose not to send an alert in TLS 1.3");
                return;
            }
            i.addAdditionalResultInfo("Only socket closed (" + i.getState().getTlsContext().getFinalSocketState() + ")");
            i.setResult(TestResult.PARTIALLY_SUCCEEDED);
            LOGGER.debug("Timeout");
            return;
        }
        assertNotNull("No Alert message received and socket is still open.", msg);
        if(AlertLevel.WARNING.getValue() == msg.getLevel().getValue() 
                && AlertDescription.CLOSE_NOTIFY.getValue() == msg.getDescription().getValue()
                && socketClosed) {
            i.addAdditionalResultInfo("Only sent Close Notify and closed socket (" + i.getState().getTlsContext().getFinalSocketState() + ")");
            i.setResult(TestResult.PARTIALLY_SUCCEEDED);
            return;
        }
        assertEquals(AssertMsgs.NoFatalAlert, AlertLevel.FATAL.getValue(), msg.getLevel().getValue().byteValue());
        assertTrue("Socket still open after fatal alert", socketClosed);
    }

    public static void receivedFatalAlert(AnnotatedState i) {
        receivedFatalAlert(i, true);
    }

    public static void executedAsPlanned(AnnotatedState i) {
        assertTrue(AssertMsgs.WorkflowNotExecuted, i.getWorkflowTrace().executedAsPlanned());
    }

    public static void receivedWarningAlert(AnnotatedState i) {
        WorkflowTrace trace = i.getWorkflowTrace();
        Validator.smartExecutedAsPlanned(i);

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        assertNotNull(AssertMsgs.NoWarningAlert, msg);
        assertEquals(AssertMsgs.NoWarningAlert, AlertLevel.WARNING.getValue(), msg.getLevel().getValue().byteValue());
    }

    public static void testAlertDescription(AnnotatedState i, AlertDescription expected, AlertMessage msg) {
        if (msg == null) {
            i.addAdditionalResultInfo("No alert received to test description for");
            return;
        }
        
        if(WorkflowTraceUtil.getLastReceivedMessage(ProtocolMessageType.ALERT, i.getWorkflowTrace()) != msg) {
            i.addAdditionalResultInfo("Received multiple Alerts - description of first Alert was tested");
        }

        AlertDescription received = AlertDescription.getAlertDescription(msg.getDescription().getValue());
        if (expected != received) {
            i.addAdditionalResultInfo("Unexpected Alert Description");
            i.addAdditionalResultInfo(String.format("Expected: %s", expected));
            i.addAdditionalResultInfo(String.format("Received: %s", received));
            i.setResult(TestResult.PARTIALLY_SUCCEEDED);
            LOGGER.debug(i.getAdditionalResultInformation());
        }
    }
    
    public static void testAlertDescription(AnnotatedState i, AlertDescription expected) {
        AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        testAlertDescription(i, expected, alert);
    }


    public static void smartExecutedAsPlanned(AnnotatedState state) {
        WorkflowTrace trace = state.getWorkflowTrace();
        if(state.getState().getTlsContext().isReceivedMessageWithWrongTls13KeyType()
                && state.getState().getTlsContext().getActiveKeySetTypeRead() != Tls13KeySetType.NONE) {
            throw new AssertionError("Peer used wrong TLS 1.3 KeySetType to protect records");
        }
        boolean executedAsPlanned = trace.executedAsPlanned();       
        if (executedAsPlanned)
            return;

        TcpFragmentationDerivation tcpFragmentation = null;
        if(state.getDerivationContainer() != null) {
            tcpFragmentation = state.getDerivationContainer().getDerivation(TcpFragmentationDerivation.class);
        }
        boolean onlyCheckActionsBeforeLastSendingFlight = tcpFragmentation != null && tcpFragmentation.getSelectedValue();

        List<TlsAction> tlsActions = trace.getTlsActions();
        TlsAction lastSendingAction = (TlsAction)trace.getLastSendingAction();
        TlsAction lastReceivingAction = (TlsAction)trace.getLastReceivingAction();
        int lastReceivingFlightIndex = lastReceivingAction != null ? tlsActions.indexOf(lastReceivingAction) : tlsActions.size();
        int lastSendingFlightIndex = lastSendingAction != null ? tlsActions.indexOf(lastSendingAction) : tlsActions.size();

        for (int i = tlsActions.size() - 1; i > 0; i--) {
            TlsAction action = tlsActions.get(i);
            if (action instanceof ReceivingAction && i == lastReceivingFlightIndex - 1) {
                lastReceivingFlightIndex = i;
            }
            if (action instanceof SendingAction && i == lastSendingFlightIndex - 1) {
                lastSendingFlightIndex = i;
            }

            // onlyCheckActionsBeforeLastSendingFlight = true
            //   <=> if (i < lastReceivingFlightIndex && i < lastSendingFlightIndex)
            // onlyCheckActionsBeforeLastSendingFlight = false
            //   <=> if (i < lastReceivingFlightIndex)
            if (i < lastReceivingFlightIndex && (i < lastSendingFlightIndex || !onlyCheckActionsBeforeLastSendingFlight)) {
                if (!action.executedAsPlanned()) {
                    throw new AssertionError(String.format("Action at index %d could not be executed as planned: %s", i, action.toString()));
                }
            }
        }

        if (!ReceivingAction.class.isAssignableFrom(trace.getLastMessageAction().getClass())) {
            throw new AssertionError("Last action is not a receiving action");
        }

        if (lastReceivingAction instanceof ReceiveAction) {
            ReceiveAction action = (ReceiveAction) lastReceivingAction;
            List<ProtocolMessage> expectedMessages = action.getExpectedMessages();
            List<ProtocolMessage> receivedMessages = action.getReceivedMessages();
            if (receivedMessages == null) {
                receivedMessages = new ArrayList<>();
            }

            TlsMessage lastExpected = (TlsMessage) expectedMessages.get(expectedMessages.size() - 1);
            if (lastExpected.getClass().equals(AlertMessage.class)) {
                if (receivedMessages.size() > 0) {
                    ProtocolMessage lastReceivedMessage = receivedMessages.get(receivedMessages.size() - 1);
                    if (lastReceivedMessage.getClass().equals(AlertMessage.class)) {
                        boolean lastMessageIsFatalAlert =
                                AlertLevel.FATAL == AlertLevel.getAlertLevel(((AlertMessage)lastReceivedMessage).getLevel().getValue());
                        if (lastMessageIsFatalAlert || onlyValidAlertsAfterFatalAlert(action.getReceivedMessages())) {
                            return;
                        }
                    } else if(lastMessagesAreTooEarlyEncryptedAlertsTls13(state, action)) {
                        return;
                    }
                }
                
                if (expectedMessages.size() > receivedMessages.size()) {
                    // try to delete the last expected AlertMessage and execute
                    // executedAsPlanned again. (In case of timeouts)
                    expectedMessages.remove(lastExpected);
                }

                if (expectedMessages.size() > 0 && !action.executedAsPlanned()) {
                    if(!expectedMessages.contains(lastExpected)) {
                       expectedMessages.add(lastExpected); 
                    }
                    throw new AssertionError("Last receive action did not execute as planned: " + action.toString());
                }

                return;
            }
        } else if (lastReceivingAction instanceof ReceiveTillAction) {
            ReceiveTillAction action = (ReceiveTillAction) lastReceivingAction;
            ProtocolMessage expectedMessage = action.getWaitTillMessage();
            List<ProtocolMessage> messages = action.getReceivedMessages();

            if (action.getReceivedMessages().isEmpty() && expectedMessage.getClass().equals(AlertMessage.class)) {
                return;
            } else if (messages.get(messages.size() - 1).getClass().equals(AlertMessage.class)) {
                return;
            }
        }

        throw new AssertionError("Last action is not a receiving action");
    }
    
    /**
     * This method is intended to allow cases where a Fatal Alert is followed
     * by a Close Notify. Multiple other alerts are also acceptable but should
     * be reviewed (we set an additional result info for this in
     * receivedFatalAlert).
     */
    private static boolean onlyValidAlertsAfterFatalAlert(List<ProtocolMessage> receivedMessages) {
        //upon calling this function, we already know there is at least 1
        //alert at the end
        if(receivedMessages.size() < 2) {
            return false;
        }
        
        boolean foundFatal = false;
        for(ProtocolMessage msg: receivedMessages) {
            if(msg instanceof AlertMessage) {
                AlertMessage alert = (AlertMessage) msg;
                if(alert.getLevel().getValue() == AlertLevel.FATAL.getValue()) {
                    foundFatal = true;
                } else if(alert.getLevel().getValue() != AlertLevel.WARNING.getValue()) {
                    //If it's neither FATAL nor WARNING, we're probably interpreting
                    //a single encrypted alert as multiple alerts. This is due to the
                    //way we parse messages; return false to fail executedAsPlanned
                    return false;
                }
            } else if(foundFatal) {
                return false;
            }
        }
        
        return foundFatal;
    }
    
    /**
     * Some implementations switch to Handshake Traffic secrets too early, we thus
     * haven't set up the decryption in the record layer yet. We attempt to decrypt
     * records with Handshake Secrets to uncover these Alerts. We apply the same
     * tolerance as for TLS 1.2 - the received messages must either end with a
     * Fatal Alert of it's own or may only consist of Alerts of valid severity after
     * receiving the first Fatal Alert (again to allow a Close Notify mostly)
     */
    private static boolean lastMessagesAreTooEarlyEncryptedAlertsTls13(AnnotatedState state, ReceiveAction lastReceiveAction) {
        ProtocolMessage lastReceivedMessage = lastReceiveAction.getReceivedMessages().get(lastReceiveAction.getReceivedMessages().size() - 1);
        List<ProtocolMessage> receivedMessages = lastReceiveAction.getReceivedMessages();
        List<AbstractRecord> receivedRecords = lastReceiveAction.getReceivedRecords();
        AbstractRecord lastAbstractRecord = lastReceiveAction.getReceivedRecords().get(receivedRecords.size() - 1);
        if(lastAbstractRecord instanceof Record) {
            Record lastReceivedRecord = (Record) lastAbstractRecord;
            int expectedFirstEncryptedRecordIndex = 0;
            if(receivedMessages.get(0) instanceof ChangeCipherSpecMessage) {
                expectedFirstEncryptedRecordIndex = 1;
            }
            if(state.getState().getConfig().getHighestProtocolVersion() == ProtocolVersion.TLS13
                    && TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.CLIENT
                    && state.getState().getTlsContext().getActiveClientKeySetType() == Tls13KeySetType.NONE
                    && lastReceivedMessage instanceof ApplicationMessage) {
                state.addAdditionalResultInfo("Received Application Message before decryption was set");
            
                List<ProtocolMessage> decryptedAlerts = new LinkedList<>();
                AlertMessage potentialAlert = null;
            
                for(int i = expectedFirstEncryptedRecordIndex; i < receivedRecords.size(); i++) {
                    Record recordToDecrypt = ((Record)receivedRecords.get(i));
                    recordToDecrypt.setSequenceNumber(Modifiable.explicit(BigInteger.valueOf(i - expectedFirstEncryptedRecordIndex)));
                    potentialAlert = tryToDecryptRecordWithHandshakeSecrets(state.getState().getTlsContext(),lastReceivedRecord);
                
                    if(potentialAlert != null) {
                        state.addAdditionalResultInfo("Client encrypted Alert too early");
                        decryptedAlerts.add(potentialAlert);
                    } else if(decryptedAlerts.size() > 0) {
                        //chain of Alerts was interrupted by other message type
                        //or decryption failed
                        state.addAdditionalResultInfo("Not all Application Messages were Alerts");
                        return false;
                    }     
                } 
            
                //replace messages for further evaluation
                for(int i = expectedFirstEncryptedRecordIndex; i < receivedMessages.size(); i++) {
                    receivedMessages.remove(i);
                    receivedMessages.add(i, decryptedAlerts.get(i - expectedFirstEncryptedRecordIndex));
                }
            
                if(potentialAlert != null && potentialAlert.getLevel().getValue() == AlertLevel.FATAL.getValue()) {
                    //last is Fatal Alert
                    return true;
                } else if(!decryptedAlerts.isEmpty()) {
                    //also allow additional (Warning) Alerts if they follow a Fatal Alert
                    return onlyValidAlertsAfterFatalAlert(decryptedAlerts);
                }
            }
        }
        return false;
    }
    
    private static AlertMessage tryToDecryptRecordWithHandshakeSecrets(TlsContext context, AbstractRecord record) {
        try {
            KeySet keySet = KeySetGenerator.generateKeySet(context, ProtocolVersion.TLS13, Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
            RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(context, keySet, context.getSelectedCipherSuite());
            RecordDecryptor dec = new RecordDecryptor(recordCipher, context);
            dec.decrypt(record);
            if(record.getContentMessageType() == ProtocolMessageType.ALERT) {
                AlertHandler handler = new AlertHandler(context);
                AlertMessage alert = handler.getParser(record.getCleanProtocolMessageBytes().getValue(), 0).parse();
                return alert;
            }
            return null;
        } catch (Exception ex) {
            return null;
        }
    }

    private static boolean traceFailedBeforeAlertAction(WorkflowTrace workflowTrace) {
        TlsAction alertReceivingAction = WorkflowTraceUtil.getFirstReceivingActionForMessage(ProtocolMessageType.ALERT, workflowTrace);
        TlsAction firstFailed = WorkflowTraceUtil.getFirstFailedAction(workflowTrace);
        return firstFailed != alertReceivingAction && workflowTrace.getTlsActions().indexOf(firstFailed) < workflowTrace.getTlsActions().indexOf(alertReceivingAction);
    }
 
}
