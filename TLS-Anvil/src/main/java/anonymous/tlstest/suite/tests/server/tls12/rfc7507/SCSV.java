/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.server.tls12.rfc7507;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.ExplicitValues;
import anonymous.tlstest.framework.annotations.MethodCondition;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ServerTest;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.SecurityCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationScope;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import anonymous.tlstest.framework.model.derivationParameter.DerivationParameter;
import anonymous.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 7507, section = "3. Server Behavior")
@ServerTest
public class SCSV extends Tls12Test {

    public ConditionEvaluationResult supportsOtherTlsVersions() {
        List<ProtocolVersion> versions = context.getSiteReport().getVersions();
        if (versions.contains(ProtocolVersion.TLS10) || versions.contains(ProtocolVersion.TLS11)) {
            return ConditionEvaluationResult.enabled("Other versions are supported");
        }
        return ConditionEvaluationResult.disabled("No other TLS versions are supported");
    }
    
    public List<DerivationParameter> getOldCiphersuites(DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        Set<CipherSuite> olderCipherSuites = new HashSet<>();
                
        List<VersionSuiteListPair> olderPairs = new ArrayList<>(context.getSiteReport().getVersionSuitePairs());
        olderPairs.removeIf(i -> i.getVersion() != ProtocolVersion.TLS10 && i.getVersion() != ProtocolVersion.TLS11);
        for(VersionSuiteListPair pair: olderPairs) {
            olderCipherSuites.addAll(pair.getCipherSuiteList());
        }
        
        for(CipherSuite cipherSuite: olderCipherSuites) {
            parameterValues.add(new CipherSuiteDerivation(cipherSuite));
        }
        
        return parameterValues;
    }
    
    public ProtocolVersion getVersionForCipherSuite(CipherSuite cipherSuite) {
        List<VersionSuiteListPair> olderPairs = new ArrayList<>(context.getSiteReport().getVersionSuitePairs());
        olderPairs.removeIf(i -> i.getVersion() != ProtocolVersion.TLS10 && i.getVersion() != ProtocolVersion.TLS11);
        for(VersionSuiteListPair versionSuite: olderPairs) {
            if(versionSuite.getCipherSuiteList().contains(cipherSuite)) {
                return versionSuite.getVersion();
            }
        }
        return null;
    }

    @TlsTest(description = "If TLS_FALLBACK_SCSV appears in ClientHello.cipher_suites and the highest protocol version " +
            "supported by the server is higher than the version indicated in ClientHello.client_version, " +
            "the server MUST respond with a fatal inappropriate_fallback alert (unless it responds with a fatal protocol_version alert " +
            "because the version indicated in ClientHello.client_version is unsupported). " +
            "The record layer version number for this alert MUST be set to either ClientHello.client_version " +
            "(as it would for the Server Hello message if the server was continuing the handshake) " +
            "or to the record layer version number used by the client.")
    @ExplicitValues(affectedTypes=DerivationType.CIPHERSUITE, methods="getOldCiphersuites")
    @MethodCondition(method = "supportsOtherTlsVersions")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.HIGH)
    public void includeFallbackSCSV(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        CipherSuite cipherSuite = derivationContainer.getDerivation(CipherSuiteDerivation.class).getSelectedValue();
        c.setDefaultSelectedProtocolVersion(getVersionForCipherSuite(cipherSuite));

        c.setDefaultSelectedCipherSuite(cipherSuite);
        c.setDefaultClientSupportedCipherSuites(cipherSuite, CipherSuite.TLS_FALLBACK_SCSV);

        ClientHelloMessage clientHello = new ClientHelloMessage(c);
        clientHello.setProtocolVersion(Modifiable.explicit(getVersionForCipherSuite(cipherSuite).getValue()));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
            new SendAction(clientHello),
            new ReceiveAction(new AlertMessage())
        );
        
        runner.execute(trace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.INAPPROPRIATE_FALLBACK, alert);
        });
    }

    @TlsTest(description = "If TLS_FALLBACK_SCSV appears in ClientHello.cipher_suites and the highest protocol version " +
            "supported by the server is higher than the version indicated in ClientHello.client_version, " +
            "the server MUST respond with a fatal inappropriate_fallback alert (unless it responds with a fatal protocol_version alert " +
            "because the version indicated in ClientHello.client_version is unsupported). " +
            "The record layer version number for this alert MUST be set to either ClientHello.client_version " +
            "(as it would for the Server Hello message if the server was continuing the handshake) " +
            "or to the record layer version number used by the client.")
    @ExplicitValues(affectedTypes=DerivationType.CIPHERSUITE, methods="getOldCiphersuites")
    @MethodCondition(method = "supportsOtherTlsVersions")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.HIGH)
    public void includeFallbackSCSV_nonRecommendedCipherSuiteOrder(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        CipherSuite cipherSuite = derivationContainer.getDerivation(CipherSuiteDerivation.class).getSelectedValue();
        c.setDefaultSelectedProtocolVersion(getVersionForCipherSuite(cipherSuite));

        c.setDefaultSelectedCipherSuite(cipherSuite);
        c.setDefaultClientSupportedCipherSuites(CipherSuite.TLS_FALLBACK_SCSV, cipherSuite);

        ClientHelloMessage clientHello = new ClientHelloMessage(c);
        clientHello.setProtocolVersion(Modifiable.explicit(getVersionForCipherSuite(cipherSuite).getValue()));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
            new SendAction(clientHello),
            new ReceiveAction(new AlertMessage())
        );
        
        runner.execute(trace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.INAPPROPRIATE_FALLBACK, alert);
        });
    }
}
