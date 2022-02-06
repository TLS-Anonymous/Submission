/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.client.tls12.rfc7366;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.DynamicValueConstraints;
import anonymous.tlstest.framework.annotations.EnforcedSenderRestriction;
import anonymous.tlstest.framework.annotations.MethodCondition;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ScopeLimitations;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.InteroperabilityCategory;
import anonymous.tlstest.framework.coffee4j.model.ModelFromScope;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.model.ModelType;
import anonymous.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;


import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
public class EncThenMacExtension extends Tls12Test {

    public ConditionEvaluationResult supportsExtension() {
        return context.getReceivedClientHelloMessage().getExtension(EncryptThenMacExtensionMessage.class) == null
                ? ConditionEvaluationResult.disabled("Target does not support Encrypt-Then-Mac") : ConditionEvaluationResult.enabled("");
    }

    public boolean isNotBlockCipher(CipherSuite cipherSuite) {
        try {
            return AlgorithmResolver.getCipherType(cipherSuite) != CipherType.BLOCK;
        } catch (Exception e) {
            return false;
        }
    }
    
    public boolean isBlockCipher(CipherSuite cipherSuite) {
        try {
            return AlgorithmResolver.getCipherType(cipherSuite) == CipherType.BLOCK;
        } catch (Exception e) {
            return false;
        }
    }

    @RFC(number = 7366, section = "3.  Applying Encrypt-then-MAC")
    @TlsTest(description = "If a server receives an encrypt-then-MAC request extension from a client and then "
            + "selects a stream or Authenticated Encryption with Associated Data (AEAD) ciphersuite, "
            + "it MUST NOT send an encrypt-then-MAC response extension back to the client.")
    @MethodCondition(method = "supportsExtension")
    @DynamicValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isNotBlockCipher")
    @ScopeLimitations(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    @EnforcedSenderRestriction
    public void sendEncThenMacExtWithNonBlockCiphers(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddEncryptThenMacExtension(true);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(trace, c).validateFinal(i -> {
            assertFalse("Workflow executed as expected", i.getWorkflowTrace().executedAsPlanned());
            Validator.receivedFatalAlert(i, false);
        });
    }
    
    @TlsTest(description = "Once the use of encrypt-then-MAC has been negotiated, processing of " +
    "TLS/DTLS packets switches from the standard: " +
    "[...]encrypt( data || MAC || pad ) " +
    "[...]to the new:" +
    "[...]encrypt( data || pad ) || MAC")
    @RFC(number = 7366, section = "3.  Applying Encrypt-then-MAC")
    @MethodCondition(method = "supportsExtension")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @DynamicValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isBlockCipher")
    @ScopeLimitations(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    public void encryptThenMacTest(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddEncryptThenMacExtension(true);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        
        runner.execute(trace, c).validateFinal(Validator::executedAsPlanned);
    }
}
