/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ResumptionResult;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class ResumptionProbe extends TlsProbe {

    private Set<CipherSuite> supportedSuites;
    private TestResult supportsDtlsCookieExchangeInResumption;
    private TestResult supportsDtlsCookieExchangeInTicketResumption;
    private TestResult respectsPskModes;

    public ResumptionProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RESUMPTION, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        this.respectsPskModes = TestResult.TRUE;
        try {
            if (getScannerConfig().getDtlsDelegate().isDTLS()) {
                supportsDtlsCookieExchangeInResumption = getSupportsDtlsCookieExchangeInResumption();
                supportsDtlsCookieExchangeInTicketResumption = getSupportsDtlsCookieExchangeInSessionTicketResumption();
                return new ResumptionResult(getSupportsSessionResumption(), getSupportsSessionTicketResumption(),
                    TestResult.NOT_TESTED_YET, TestResult.NOT_TESTED_YET, TestResult.NOT_TESTED_YET,
                    TestResult.NOT_TESTED_YET, supportsDtlsCookieExchangeInResumption,
                    supportsDtlsCookieExchangeInTicketResumption, respectsPskModes);
            } else {
                supportsDtlsCookieExchangeInResumption = TestResult.NOT_TESTED_YET;
                supportsDtlsCookieExchangeInTicketResumption = TestResult.NOT_TESTED_YET;
                return new ResumptionResult(getSupportsSessionResumption(), getSupportsSessionTicketResumption(),
                    getIssuesSessionTicket(), getSupportsTls13Psk(PskKeyExchangeMode.PSK_DHE_KE),
                    getSupportsTls13Psk(PskKeyExchangeMode.PSK_KE), getSupports0rtt(),
                    supportsDtlsCookieExchangeInResumption, supportsDtlsCookieExchangeInTicketResumption,
                    respectsPskModes);
            }
        } catch (Exception e) {
            LOGGER.error("Could not scan for " + getProbeName(), e);
            return new ResumptionResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST,
                TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST,
                TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST,
                TestResult.ERROR_DURING_TEST);
        }
    }

    private TestResult getSupportsDtlsCookieExchangeInResumption() {
        try {
            Config tlsConfig = createConfig();
            WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
                .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, tlsConfig.getDefaultRunningMode());
            addAlertToTrace(trace);
            trace.addTlsAction(new ResetConnectionAction());
            trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
            trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage(tlsConfig)));
            State state = new State(tlsConfig, trace);
            executeState(state);
            return state.getWorkflowTrace().executedAsPlanned() ? TestResult.TRUE : TestResult.FALSE;
        } catch (Exception e) {
            LOGGER.error("Could not test for support for dtls cookie exchange in SessionResumption");
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult getSupportsSessionResumption() {
        try {
            Config tlsConfig = createConfig();
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.FULL_RESUMPTION);
            State state = new State(tlsConfig);
            WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
                .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, tlsConfig.getDefaultRunningMode());
            addAlertToTrace(trace);
            trace.addTlsAction(new ResetConnectionAction());
            tlsConfig.setDtlsCookieExchange(supportsDtlsCookieExchangeInResumption == TestResult.TRUE);
            trace.addTlsActions(new WorkflowConfigurationFactory(tlsConfig)
                .createWorkflowTrace(WorkflowTraceType.RESUMPTION, tlsConfig.getDefaultRunningMode()).getTlsActions());
            state = new State(tlsConfig, trace);
            executeState(state);
            return state.getWorkflowTrace().executedAsPlanned() == true ? TestResult.TRUE : TestResult.FALSE;
        } catch (Exception e) {
            LOGGER.error("Could not test for support for SessionResumption");
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult getSupportsDtlsCookieExchangeInSessionTicketResumption() {
        try {
            Config tlsConfig = createConfig();
            tlsConfig.setAddSessionTicketTLSExtension(true);
            WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
                .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
            trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
            trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
            trace.addTlsAction(
                new ReceiveAction(new NewSessionTicketMessage(), new ChangeCipherSpecMessage(), new FinishedMessage()));
            addAlertToTrace(trace);
            trace.addTlsAction(new ResetConnectionAction());
            trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
            trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage(tlsConfig)));
            State state = new State(tlsConfig, trace);
            executeState(state);
            return state.getWorkflowTrace().executedAsPlanned() ? TestResult.TRUE : TestResult.FALSE;
        } catch (Exception e) {
            LOGGER.error("Could not test for support for dtls cookie exchange in SessionTicketResumption");
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult getSupportsSessionTicketResumption() {
        try {
            Config tlsConfig = createConfig();
            tlsConfig.setAddSessionTicketTLSExtension(true);
            WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
                .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
            trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
            trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
            trace.addTlsAction(
                new ReceiveAction(new NewSessionTicketMessage(), new ChangeCipherSpecMessage(), new FinishedMessage()));
            addAlertToTrace(trace);
            trace.addTlsAction(new ResetConnectionAction());
            tlsConfig.setDtlsCookieExchange(supportsDtlsCookieExchangeInResumption == TestResult.TRUE);
            trace.addTlsActions(new WorkflowConfigurationFactory(tlsConfig)
                .createWorkflowTrace(WorkflowTraceType.RESUMPTION, tlsConfig.getDefaultRunningMode()).getTlsActions());
            State state = new State(tlsConfig, trace);
            executeState(state);
            return state.getWorkflowTrace().executedAsPlanned() == true ? TestResult.TRUE : TestResult.FALSE;
        } catch (Exception e) {
            LOGGER.error("Could not test for support for SessionTicketResumption");
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult isKeyShareExtensionNegotiated(State state) {
        List<HandshakeMessage> handshakes = WorkflowTraceUtil.getAllReceivedHandshakeMessages(state.getWorkflowTrace());
        List<ServerHelloMessage> hellos = handshakes.stream().filter(message -> message instanceof ServerHelloMessage)
            .map(message -> (ServerHelloMessage) message).collect(Collectors.toList());
        if (hellos.size() < 2) {
            return TestResult.COULD_NOT_TEST;
        }
        ServerHelloMessage second = hellos.get(1);
        KeyShareExtensionMessage keyShareExtensionMessage = second.getExtension(KeyShareExtensionMessage.class);
        return second.containsExtension(ExtensionType.KEY_SHARE) ? TestResult.TRUE : TestResult.FALSE;
    }

    private TestResult getSupportsTls13Psk(PskKeyExchangeMode exchangeMode) {
        try {
            Config tlsConfig = createTls13Config();
            List<PskKeyExchangeMode> pskKex = new LinkedList<>();
            pskKex.add(exchangeMode);
            tlsConfig.setPSKKeyExchangeModes(pskKex);
            tlsConfig.setAddPSKKeyExchangeModesExtension(true);
            tlsConfig.setAddPreSharedKeyExtension(true);
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.FULL_TLS13_PSK);
            State state = new State(tlsConfig);
            executeState(state);

            MessageAction lastRcv = (MessageAction) state.getWorkflowTrace().getLastReceivingAction();
            if (lastRcv.executedAsPlanned()) {
                // Check PSK Modes
                TestResult keyShareExtensionNegotiated = isKeyShareExtensionNegotiated(state);
                TestResult keyShareRequired = TestResult.of(exchangeMode.equals(PskKeyExchangeMode.PSK_DHE_KE));
                if (!keyShareExtensionNegotiated.equals(keyShareRequired)) {
                    if (!TestResult.COULD_NOT_TEST.equals(keyShareExtensionNegotiated)) {
                        respectsPskModes = TestResult.FALSE;
                    }
                }
                return TestResult.TRUE;
            }
            return TestResult.FALSE;
        } catch (Exception e) {
            LOGGER.error("Could not test for support for Tls13Psk (" + exchangeMode + ")");
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult getSupports0rtt() {
        try {
            Config tlsConfig = createTls13Config();
            tlsConfig.setAddPSKKeyExchangeModesExtension(true);
            tlsConfig.setAddPreSharedKeyExtension(true);
            tlsConfig.setAddEarlyDataExtension(true);
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.FULL_ZERO_RTT);
            State state = new State(tlsConfig);
            executeState(state);

            EncryptedExtensionsMessage encExt =
                state.getWorkflowTrace().getLastReceivedMessage(EncryptedExtensionsMessage.class);
            if (encExt != null && encExt.containsExtension(ExtensionType.EARLY_DATA)) {
                return TestResult.TRUE;
            }
            return TestResult.FALSE;
        } catch (Exception e) {
            LOGGER.error("Could not test for support for Tls13PskDhe");
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult getIssuesSessionTicket() {
        try {
            Config tlsConfig = createTls13Config();
            List<PskKeyExchangeMode> pskKex = new LinkedList<>();
            pskKex.add(PskKeyExchangeMode.PSK_DHE_KE);
            pskKex.add(PskKeyExchangeMode.PSK_KE);
            tlsConfig.setPSKKeyExchangeModes(pskKex);
            tlsConfig.setAddPSKKeyExchangeModesExtension(true);
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
            State state = new State(tlsConfig);
            state.getWorkflowTrace().addTlsAction(new ReceiveAction(tlsConfig.getDefaultClientConnection().getAlias(),
                new NewSessionTicketMessage(false)));
            executeState(state);

            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.NEW_SESSION_TICKET,
                state.getWorkflowTrace())) {
                return TestResult.TRUE;
            }
            return TestResult.FALSE;
        } catch (Exception e) {
            LOGGER.error("Could not test for support for Tls13SessionTickets");
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private void addAlertToTrace(WorkflowTrace trace) {
        AlertMessage alert = new AlertMessage();
        alert.setConfig(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
        trace.addTlsAction(new SendAction(alert));
    }

    private Config createConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setDefaultClientSupportedCipherSuites(new ArrayList<>(supportedSuites));
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
        return tlsConfig;
    }

    private Config createTls13Config() {
        Config tlsConfig = getScannerConfig().createConfig();
        List<NamedGroup> tls13Groups = new LinkedList<>();
        for (NamedGroup group : NamedGroup.getImplemented()) {
            if (group.isTls13()) {
                tls13Groups.add(group);
            }
        }
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(CipherSuite.getTls13CipherSuites());
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsConfig.setSupportedVersions(ProtocolVersion.TLS13);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setDefaultClientKeyShareNamedGroups(tls13Groups);
        tlsConfig.setAddCertificateStatusRequestExtension(true);
        tlsConfig.setUseFreshRandom(true);
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(
            SignatureAndHashAlgorithm.getImplementedTls13SignatureAndHashAlgorithms());
        tlsConfig.setTls13BackwardsCompatibilityMode(Boolean.TRUE);
        return tlsConfig;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.getCipherSuites() != null && (report.getCipherSuites().size() > 0);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        supportedSuites = report.getCipherSuites();
        supportedSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        supportedSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new ResumptionResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST,
            TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST,
            TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }
}
