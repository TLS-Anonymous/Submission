/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.server.tls12.rfc7465;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import anonymous.tlstest.framework.TestContext;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.DynamicValueConstraints;
import anonymous.tlstest.framework.annotations.ManualConfig;
import anonymous.tlstest.framework.annotations.MethodCondition;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ServerTest;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.CryptoCategory;
import anonymous.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.SecurityCategory;
import anonymous.tlstest.framework.constants.AssertMsgs;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import anonymous.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;

import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 7465, section = "2")
@ServerTest
public class RC4Ciphersuites extends Tls12Test {

    public ConditionEvaluationResult supportsRC4(ExtensionContext context) {
        List<CipherSuite> supported = new ArrayList<>(this.context.getSiteReport().getCipherSuites());
        supported.removeIf(i -> !i.toString().contains("RC4"));

        return supported.size() == 0 ? ConditionEvaluationResult.disabled("No RC4 Ciphersuite supported") : ConditionEvaluationResult.enabled("");
    }

    public boolean isRC4(CipherSuite cipherSuite) {
        return cipherSuite.toString().contains("RC4");
    }

    public boolean isNonRC4(CipherSuite cipherSuite) {
        return !isRC4(cipherSuite);
    }
    

    @TlsTest(description = "TLS servers MUST NOT select an RC4 cipher suite when a TLS client " +
            "sends such a cipher suite in the ClientHello message.")
    @ManualConfig(DerivationType.CIPHERSUITE)
    @MethodCondition(method = "supportsRC4")
    @DynamicValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods="isNonRC4")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @CryptoCategory(SeverityLevel.MEDIUM)
    @DeprecatedFeatureCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.HIGH)
    public void offerRC4AndOtherCiphers(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        CipherSuite selectedCipherSuite = derivationContainer.getDerivation(CipherSuiteDerivation.class).getSelectedValue();

        List<CipherSuite> implemented = new ArrayList<>(TestContext.getInstance().getSiteReport().getCipherSuites());
        implemented.removeIf(i -> !i.toString().contains("RC4"));
        c.setDefaultClientSupportedCipherSuites(implemented);
        c.getDefaultClientSupportedCipherSuites().add(selectedCipherSuite);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.executedAsPlanned(i);

            ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertArrayEquals(AssertMsgs.UnexpectedCipherSuite, selectedCipherSuite.getByteValue(), msg.getSelectedCipherSuite().getValue());
        });
    }

    @TlsTest(description = "If the TLS client only offers RC4 cipher suites, the TLS server " +
            "MUST terminate the handshake. The TLS server MAY send the " +
            "insufficient_security fatal alert in this case.")
    @DynamicValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods="isRC4")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @CryptoCategory(SeverityLevel.MEDIUM)
    @DeprecatedFeatureCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void onlyRC4Suites(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }



}
