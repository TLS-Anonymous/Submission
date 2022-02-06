/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.client.tls12.rfc7465;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.DynamicValueConstraints;
import anonymous.tlstest.framework.annotations.EnforcedSenderRestriction;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.TestDescription;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.CryptoCategory;
import anonymous.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.SecurityCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.testClasses.Tls12Test;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 7465, section = "2")
@ClientTest
public class RC4Ciphersuites extends Tls12Test {
  
    public boolean isRC4CipherSuite(CipherSuite cipherSuite) {
        return cipherSuite.name().contains("RC4");
    }

    @Test
    @TestDescription("TLS clients MUST NOT include RC4 cipher suites in the ClientHello message.")
    @SecurityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @DeprecatedFeatureCategory(SeverityLevel.HIGH)
    @CryptoCategory(SeverityLevel.MEDIUM)
    public void offersRC4Ciphersuites() {
        List<CipherSuite> supported = new ArrayList<>(this.context.getSiteReport().getCipherSuites());
        supported.removeIf(i -> !i.toString().contains("RC4"));
        if (supported.size() > 0) {
            throw new AssertionError("Client supports RC4 Ciphersuites");
        }
    }

    @TlsTest(description = "TLS servers MUST NOT select an RC4 cipher suite when a TLS client sends such " +
            "a cipher suite in the ClientHello message.")
    @DynamicValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods="isRC4CipherSuite")
    @SecurityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @DeprecatedFeatureCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    @CryptoCategory(SeverityLevel.MEDIUM)
    @EnforcedSenderRestriction
    public void selectRC4CipherSuite(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
