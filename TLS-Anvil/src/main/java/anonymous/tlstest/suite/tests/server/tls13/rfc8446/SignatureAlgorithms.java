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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.ExplicitValues;
import anonymous.tlstest.framework.annotations.ManualConfig;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ScopeExtensions;
import anonymous.tlstest.framework.annotations.ServerTest;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.InteroperabilityCategory;
import anonymous.tlstest.framework.annotations.categories.SecurityCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationScope;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.model.derivationParameter.DerivationParameter;
import anonymous.tlstest.framework.model.derivationParameter.SigAndHashDerivation;
import anonymous.tlstest.framework.testClasses.Tls13Test;

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 8446, section = "4.2.3 Signature Algorithms")
@ServerTest
public class SignatureAlgorithms extends Tls13Test {

    @TlsTest(description = "If a server is authenticating via a certificate "
            + "and the client has not sent a \"signature_algorithms\" extension, "
            + "then the server MUST abort the handshake with "
            + "a \"missing_extension\" alert (see Section 9.2).")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void omitSignatureAlgorithmsExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddSignatureAndHashAlgorithmsExtension(false);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage msg = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.MISSING_EXTENSION, msg);
        });
    }

    public List<DerivationParameter> getLegacySigHashAlgoritms(DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        List<SignatureAndHashAlgorithm> algos = SignatureAndHashAlgorithm.getImplemented().stream()
                .filter(i -> !i.suitedForSigningTls13Messages())
                .collect(Collectors.toList());
        algos.forEach(i -> parameterValues.add(new SigAndHashDerivation(i)));
        return parameterValues;
    }

    @TlsTest(description = "These values refer solely to signatures " +
        "which appear in certificates (see Section 4.4.2.2) and are not " +
        "defined for use in signed TLS handshake messages, although they " +
        "MAY appear in \"signature_algorithms\" and " +
        "\"signature_algorithms_cert\" for backward compatibility with " +
        "TLS 1.2. [...]" + 
        "Clients " +
        "offering these values MUST list them as the lowest priority " +
        "(listed after all other algorithms in SignatureSchemeList).")
    @ScopeExtensions(DerivationType.SIG_HASH_ALGORIHTM)
    @ManualConfig(DerivationType.SIG_HASH_ALGORIHTM)
    @ExplicitValues(affectedTypes = DerivationType.SIG_HASH_ALGORIHTM, methods = "getLegacySigHashAlgoritms")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.MEDIUM)
    public void offerLegacySignatureAlgorithms(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        SignatureAndHashAlgorithm selectedSigHash = derivationContainer.getDerivation(SigAndHashDerivation.class).getSelectedValue();

        List<SignatureAndHashAlgorithm> algos = SignatureAndHashAlgorithm.getImplemented().stream()
                .filter(SignatureAndHashAlgorithm::suitedForSigningTls13Messages)
                .collect(Collectors.toList());
        algos.add(0, selectedSigHash);

        c.setDefaultClientSupportedSignatureAndHashAlgorithms(algos);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            CertificateVerifyMessage certVerifyMsg = i.getWorkflowTrace().getFirstReceivedMessage(CertificateVerifyMessage.class);
            assertNotNull(certVerifyMsg);
            SignatureAndHashAlgorithm sigHashAlg = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(certVerifyMsg.getSignatureHashAlgorithm().getValue());
            assertTrue("Invalid SignatureAndHashAlgorithm negotiated", sigHashAlg.suitedForSigningTls13Messages());
        });
    }

    @TlsTest(description = "These values refer solely to signatures " +
        "which appear in certificates (see Section 4.4.2.2) and are not " +
        "defined for use in signed TLS handshake messages, although they " +
        "MAY appear in \"signature_algorithms\" and " +
        "\"signature_algorithms_cert\" for backward compatibility with " +
        "TLS 1.2. [...]" + 
        "In TLS 1.2, the extension contained hash/signature pairs.  The " +
        "pairs are encoded in two octets, so SignatureScheme values have " +
        "been allocated to align with TLS 1.2's encoding.  Some legacy " +
        "pairs are left unallocated.  These algorithms are deprecated as of " +
        "TLS 1.3.  They MUST NOT be offered or negotiated by any " +
        "implementation.  In particular, MD5 [SLOTH], SHA-224, and DSA " +
        "MUST NOT be used.")
    @ScopeExtensions(DerivationType.SIG_HASH_ALGORIHTM)
    @ExplicitValues(affectedTypes = DerivationType.SIG_HASH_ALGORIHTM, methods = "getLegacySigHashAlgoritms")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.MEDIUM)
    public void offerOnlyLegacySignatureAlgorithms(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "A server receiving a ClientHello MUST correctly ignore all " +
        "unrecognized cipher suites, extensions, and other parameters.")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void includeUnknownSignatureAndHashAlgorithm(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddSignatureAndHashAlgorithmsExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        ClientHelloMessage clientHello = (ClientHelloMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        SignatureAndHashAlgorithmsExtensionMessage algorithmsExtension = clientHello.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class);
        algorithmsExtension.setSignatureAndHashAlgorithms(Modifiable.insert(new byte[]{(byte) 0xfe, 0x44}, 0));

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }
}
