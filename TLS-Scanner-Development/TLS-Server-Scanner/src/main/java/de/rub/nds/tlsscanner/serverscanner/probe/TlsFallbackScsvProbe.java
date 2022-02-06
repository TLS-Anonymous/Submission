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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.TlsFallbackScsvResult;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class TlsFallbackScsvProbe extends TlsProbe {

    private ProtocolVersion secondHighestVersion;

    public TlsFallbackScsvProbe(ParallelExecutor parallelExecutor, ScannerConfig scannerConfig) {
        super(parallelExecutor, ProbeType.TLS_FALLBACK_SCSV, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        Config tlsConfig = getScannerConfig().createConfig();

        List<CipherSuite> cipherSuites = new ArrayList<>(CipherSuite.getImplemented());
        cipherSuites.add(CipherSuite.TLS_FALLBACK_SCSV);
        tlsConfig.setDefaultSelectedProtocolVersion(this.secondHighestVersion);
        tlsConfig.setDefaultHighestClientProtocolVersion(this.secondHighestVersion);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setHighestProtocolVersion(this.secondHighestVersion);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        List<NamedGroup> namedGroups = Arrays.asList(NamedGroup.values());

        tlsConfig.setDefaultClientNamedGroups(namedGroups);
        State state = new State(tlsConfig, getWorkflowTrace());
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return new TlsFallbackScsvResult(TestResult.TRUE);
        } else {
            LOGGER.debug("Received ServerHelloMessage");
            LOGGER.debug("{}", state.getWorkflowTrace());
            return new TlsFallbackScsvResult(TestResult.FALSE);
        }
    }

    private WorkflowTrace getWorkflowTrace() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        AlertMessage alertMessage = new AlertMessage();
        alertMessage.setDescription(AlertDescription.INAPPROPRIATE_FALLBACK.getValue());
        alertMessage.setLevel(AlertLevel.FATAL.getValue());
        trace.addTlsAction(new ReceiveAction(alertMessage));
        return trace;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.isProbeAlreadyExecuted(ProbeType.PROTOCOL_VERSION) && report.getVersions().size() > 1;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new TlsFallbackScsvResult(TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        List<ProtocolVersion> versions = new ArrayList<>(report.getVersions());
        Collections.sort(versions);
        this.secondHighestVersion = versions.get(versions.size() - 2);
    }
}
