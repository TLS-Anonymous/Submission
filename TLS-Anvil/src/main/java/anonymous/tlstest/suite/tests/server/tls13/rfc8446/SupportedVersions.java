/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.ExplicitValues;
import anonymous.tlstest.framework.annotations.KeyExchange;
import anonymous.tlstest.framework.annotations.ManualConfig;
import anonymous.tlstest.framework.annotations.MethodCondition;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ScopeExtensions;
import anonymous.tlstest.framework.annotations.ServerTest;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.InteroperabilityCategory;
import anonymous.tlstest.framework.constants.KeyExchangeType;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationScope;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import anonymous.tlstest.framework.model.derivationParameter.DerivationParameter;
import anonymous.tlstest.framework.model.derivationParameter.ProtocolVersionDerivation;
import anonymous.tlstest.framework.testClasses.Tls13Test;

import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.stream.Collectors;

import static org.junit.Assert.*;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 8446, section = "4.2.1 Supported Versions")
@ServerTest
public class SupportedVersions extends Tls13Test {

    public ConditionEvaluationResult supportsTls12() {
        if (context.getSiteReport().getVersions().contains(ProtocolVersion.TLS12)) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("TLS 1.2 is not supported by the server.");
    }

    @TlsTest(description = "The extension contains a list of supported versions in "
            + "preference order, with the most preferred version first. [...]"
            + "If the \"supported_versions\" extension is present, the server MUST negotiate using that extension as described in Section 4.2.1.")
    @RFC(number = 8446, section = "4.2.1 Supported Versions and D.2.  Negotiating with an Older Client")
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void testVersionPreferrence(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);

        c.setSupportedVersions(ProtocolVersion.TLS12, ProtocolVersion.TLS13);
        c.getDefaultClientSupportedCipherSuites().addAll(
                CipherSuite.getImplemented().stream().filter(CipherSuite::isTLS13).collect(Collectors.toList())
        );

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

    @TlsTest(description = "If this extension is not present, servers which are compliant "
            + "with this specification and which also support TLS 1.2 MUST "
            + "negotiate TLS 1.2 or prior as specified in [RFC5246][...]"
            + "If the \"supported_versions\" extension is not present, the server MUST negotiate the minimum of ClientHello.legacy_version and TLS 1.2.")
    @RFC(number = 8446, section = "4.2.1 Supported Versions and D.2.  Negotiating with an Older Client")
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void omitSupportedVersionsExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        
        c.setAddSupportedVersionsExtension(false);
        c.setHighestProtocolVersion(ProtocolVersion.TLS12);
        c.getDefaultClientSupportedCipherSuites().addAll(
                CipherSuite.getImplemented().stream().filter(CipherSuite::isTLS13).collect(Collectors.toList())
        );

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }
    
    @TlsTest(description = "If the \"supported_versions\" extension is absent and the server only supports versions greater than ClientHello.legacy_version, the server MUST abort the handshake with a \"protocol_version\" alert.")
    @RFC(number = 8446, section = "D.2.  Negotiating with an Older Client")
    @ScopeExtensions(DerivationType.PROTOCOL_VERSION)
    @ExplicitValues(affectedTypes = DerivationType.PROTOCOL_VERSION, methods = "getUnsupportedProtocolVersions")
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void supportedVersionsAbsentOnlyUnsupportedLegacyVersion(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddSupportedVersionsExtension(false);
        c.setHighestProtocolVersion(ProtocolVersion.TLS12);
        byte[] chosenUnsupportedVersion = derivationContainer.getDerivation(ProtocolVersionDerivation.class).getSelectedValue();
        
        WorkflowTrace workflowTrace = new WorkflowTrace();
        ClientHelloMessage clientHello = new ClientHelloMessage(c);
        clientHello.setProtocolVersion(Modifiable.explicit(chosenUnsupportedVersion));
        workflowTrace.addTlsAction(new SendAction(clientHello));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            Validator.testAlertDescription(i, AlertDescription.PROTOCOL_VERSION);
        });
    }
    
    public List<DerivationParameter> getUnsupportedProtocolVersions(DerivationScope scope) {
        List<ProtocolVersion> consideredVersions = new LinkedList<>();
        consideredVersions.add(ProtocolVersion.SSL2);
        consideredVersions.add(ProtocolVersion.SSL3);
        consideredVersions.add(ProtocolVersion.TLS10);
        consideredVersions.add(ProtocolVersion.TLS11);
        consideredVersions.add(ProtocolVersion.TLS12);
        context.getSiteReport().getVersions().forEach(version -> consideredVersions.remove(version));
        List<DerivationParameter> parameterValues = new LinkedList<>();
        consideredVersions.forEach(version -> parameterValues.add(new ProtocolVersionDerivation(version.getValue())));
        return parameterValues;
    }

    @TlsTest(description = "If this extension is present in the ClientHello, "
            + "servers MUST NOT use the ClientHello.legacy_version value "
            + "for version negotiation and MUST use only the \"supported_versions\" "
            + "extension to determine client preferences.")
    @MethodCondition(method = "supportsTls12")
    @ManualConfig(DerivationType.CIPHERSUITE)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void oldLegacyVersion(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        CipherSuite tls13CipherSuite = derivationContainer.getDerivation(CipherSuiteDerivation.class).getSelectedValue();
        c.setDefaultClientSupportedCipherSuites(context.getSiteReport().getCipherSuites().stream().filter(i -> !i.isTLS13()).collect(Collectors.toList()));
        c.getDefaultClientSupportedCipherSuites().add(tls13CipherSuite);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.getFirstSendMessage(ClientHelloMessage.class)
                .setProtocolVersion(Modifiable.explicit(new byte[]{3, 3}));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);
            assertEquals("Wrong TLS Version selected", ProtocolVersion.TLS13, i.getState().getTlsContext().getSelectedProtocolVersion());
        });
    }

    @TlsTest(description = "Servers MUST only select a version of TLS present in " +
        "that extension and MUST ignore any unknown versions that are present in that extension.")
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    public void unknownVersion(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        workflowTrace.getFirstSendMessage(ClientHelloMessage.class)
                .getExtension(SupportedVersionsExtensionMessage.class)
                .setSupportedVersions(Modifiable.explicit(new byte[]{0x05, 0x05, 0x03, 0x04}));

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

    @TlsTest(description = "Servers MUST be prepared to receive ClientHellos that "
            + "include this extension but do not include 0x0304 in the list of versions. "
            + "A server which negotiates a version of TLS prior to TLS 1.3 MUST "
            + "set ServerHello.version and MUST NOT send the \"supported_versions\" extension.")
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    public void supportedVersionsWithoutTls13(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);
        c.setAddSupportedVersionsExtension(true);
        c.setSupportedVersions(ProtocolVersion.TLS12);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            WorkflowTrace trace = i.getWorkflowTrace();
            ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertArrayEquals("Invalid ProtocolVersion", new byte[]{0x03, 0x03}, msg.getProtocolVersion().getValue());
            assertNull("Received supported_versions extension", msg.getExtension(SupportedVersionsExtensionMessage.class));
        });
    }

    @TlsTest(description = "All TLS 1.3 " +
            "ServerHello messages MUST contain the \"supported_versions\" " +
            "extension."
            + " [...] A server which negotiates TLS 1.3 MUST "
            + "respond by sending a \"supported_versions\" extension "
            + "containing the selected version value (0x0304). "
            + "It MUST set the ServerHello.legacy_version field to 0x0303 (TLS 1.2).")
    @RFC(number = 8446, section = "4.1.3.  Server Hello and 4.2.1 Supported Versions")
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    public void tls13Handshake(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);
            WorkflowTrace trace = i.getWorkflowTrace();
            ServerHelloMessage serverHello = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            SupportedVersionsExtensionMessage supportedVersions = serverHello.getExtension(SupportedVersionsExtensionMessage.class);

            assertNotNull("No SupportedVersions extension received in ServerHello", supportedVersions);
            assertArrayEquals("legacy_version must be 0x0303", ProtocolVersion.TLS12.getValue(), serverHello.getProtocolVersion().getValue());
            assertTrue("SupportedVersions extension does not contain 0x0304",
                    ProtocolVersion.getProtocolVersions(supportedVersions.getSupportedVersions().getValue()).contains(ProtocolVersion.TLS13)
            );
        });
    }

    @TlsTest(description = "If this extension is present in the ClientHello, "
            + "servers MUST NOT use the ClientHello.legacy_version value for "
            + "version negotiation and MUST use only the \"supported_versions\" "
            + "extension to determine client preferences.")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
    public void setLegacyVersionTo0304(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveAction(new AlertMessage())
        );

        ClientHelloMessage chm = workflowTrace.getFirstSendMessage(ClientHelloMessage.class);
        chm.setProtocolVersion(Modifiable.explicit(ProtocolVersion.TLS13.getValue()));
        chm.getExtension(SupportedVersionsExtensionMessage.class).setSupportedVersions(Modifiable.explicit(ProtocolVersion.TLS12.getValue()));


        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "If this extension is not present, servers which are compliant with " +
            "this specification and which also support TLS 1.2 MUST negotiate " +
            "TLS 1.2 or prior as specified in [RFC5246], even if " +
            "ClientHello.legacy_version is 0x0304 or later. Servers MAY abort the " +
            "handshake upon receiving a ClientHello with legacy_version 0x0304 or " +
            "later.")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void setLegacyVersionTo0304WithoutSVExt(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddSupportedVersionsExtension(false);
        
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveAction(new AlertMessage())
        );

        ClientHelloMessage chm = workflowTrace.getFirstSendMessage(ClientHelloMessage.class);
        chm.setProtocolVersion(Modifiable.explicit(ProtocolVersion.TLS13.getValue()));

        //note that we only offer TLS 1.3 cipher suites, the server is hence
        //forced to abort the handshake
        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

}
