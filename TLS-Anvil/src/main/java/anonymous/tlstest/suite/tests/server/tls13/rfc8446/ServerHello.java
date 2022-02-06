/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.server.tls13.rfc8446;

import anonymous.tlstest.suite.tests.both.tls13.rfc8446.SharedExtensionTests;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.DynamicValueConstraints;
import anonymous.tlstest.framework.annotations.KeyExchange;
import anonymous.tlstest.framework.annotations.MethodCondition;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ServerTest;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.InteroperabilityCategory;
import anonymous.tlstest.framework.annotations.categories.SecurityCategory;
import anonymous.tlstest.framework.constants.AssertMsgs;
import anonymous.tlstest.framework.constants.KeyExchangeType;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationScope;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.model.derivationParameter.DerivationParameter;
import anonymous.tlstest.framework.model.derivationParameter.ProtocolVersionDerivation;
import anonymous.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.*;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 8446, section = "4.1.3 Server Hello")
@ServerTest
public class ServerHello extends Tls13Test {

    public ConditionEvaluationResult supportsTls12() {
        if (context.getSiteReport().getVersions().contains(ProtocolVersion.TLS12))
            return ConditionEvaluationResult.enabled("");
        return ConditionEvaluationResult.disabled("No TLS 1.2 support");
    }
    
    public ConditionEvaluationResult supportsTls11() {
        if (context.getSiteReport().getVersions().contains(ProtocolVersion.TLS11))
            return ConditionEvaluationResult.enabled("");
        return ConditionEvaluationResult.disabled("No TLS 1.1 support");
    }
    
    public ConditionEvaluationResult supportsTls10() {
        if (context.getSiteReport().getVersions().contains(ProtocolVersion.TLS10))
            return ConditionEvaluationResult.enabled("");
        return ConditionEvaluationResult.disabled("No TLS 1.0 support");
    }
    
    @TlsTest(description = "In TLS 1.3, the TLS server indicates its version using the \"supported_versions\" " +
            "extension (Section 4.2.1), and the legacy_version field MUST be " +
            "set to 0x0303, which is the version number for TLS 1.2.")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void testLegacyVersion(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new CertificateVerifyMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.executedAsPlanned(i);

            ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertNotNull(AssertMsgs.ServerHelloNotReceived, msg);
            assertArrayEquals("Invalid legacy version", new byte[]{0x03, 0x03}, msg.getProtocolVersion().getValue());
        });
    }

    @TlsTest(description = "The last 8 bytes MUST be overwritten as described " +
            "below if negotiating TLS 1.2 or TLS 1.1, but the remaining bytes MUST be random. [...]" +
            "TLS 1.3 servers which negotiate TLS 1.2 or below in " +
            "response to a ClientHello MUST set the last 8 bytes of their Random " +
            "value specially in their ServerHello. [...]" +
            "If negotiating TLS 1.2, TLS 1.3 servers MUST set the last 8 bytes of " +
            "their Random value to the bytes: 44 4F 57 4E 47 52 44 01")
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void testServerRandomFor12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.executedAsPlanned(i);

            ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertNotNull(AssertMsgs.ServerHelloNotReceived, msg);
            byte[] random = msg.getRandom().getValue();
            assertArrayEquals("Invalid random", new byte[]{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01},
                    Arrays.copyOfRange(random, random.length - 8, random.length));
        });
    }
    
    @TlsTest(description = "The last 8 bytes MUST be overwritten as described " +
            "below if negotiating TLS 1.2 or TLS 1.1, but the remaining bytes MUST be random. [...]" +
            "TLS 1.3 servers which negotiate TLS 1.2 or below in " +
            "response to a ClientHello MUST set the last 8 bytes of their Random " +
            "value specially in their ServerHello. [...]" +
            "If negotiating TLS 1.1 or below, TLS 1.3 servers MUST, and TLS 1.2 " +
            "servers SHOULD, set the last 8 bytes of their ServerHello.Random " +
            "value to the bytes: 44 4F 57 4E 47 52 44 00")
    @MethodCondition(method = "supportsTls11")
    @DynamicValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isTls11CipherSuite")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void testServerRandomFor11(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);
        config.setHighestProtocolVersion(ProtocolVersion.TLS11);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        workflowTrace.addTlsActions(
                new SendAction(clientHello),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.execute(workflowTrace, config).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.executedAsPlanned(i);

            ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertNotNull(AssertMsgs.ServerHelloNotReceived, msg);
            byte[] random = msg.getRandom().getValue();
            assertArrayEquals("Invalid random", new byte[]{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00},
                    Arrays.copyOfRange(random, random.length - 8, random.length));
        });
    }
    
    @TlsTest(description = "The last 8 bytes MUST be overwritten as described " +
            "below if negotiating TLS 1.2 or TLS 1.1, but the remaining bytes MUST be random. [...]" +
            "TLS 1.3 servers which negotiate TLS 1.2 or below in " +
            "response to a ClientHello MUST set the last 8 bytes of their Random " +
            "value specially in their ServerHello. [...]" +
            "If negotiating TLS 1.1 or below, TLS 1.3 servers MUST, and TLS 1.2 " +
            "servers SHOULD, set the last 8 bytes of their ServerHello.Random " +
            "value to the bytes: 44 4F 57 4E 47 52 44 00")
    @MethodCondition(method = "supportsTls10")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @DynamicValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isTls10CipherSuite")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void testServerRandomFor10(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);
        config.setHighestProtocolVersion(ProtocolVersion.TLS10);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        workflowTrace.addTlsActions(
                new SendAction(clientHello),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.execute(workflowTrace, config).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.executedAsPlanned(i);

            ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertNotNull(AssertMsgs.ServerHelloNotReceived, msg);
            byte[] random = msg.getRandom().getValue();
            assertArrayEquals("Invalid random", new byte[]{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00},
                    Arrays.copyOfRange(random, random.length - 8, random.length));
        });
    }
    
    public boolean isTls10CipherSuite(CipherSuite cipherSuite) {
        return cipherSuite.isSupportedInProtocol(ProtocolVersion.TLS10);
    }
    
    public boolean isTls11CipherSuite(CipherSuite cipherSuite) {
        return cipherSuite.isSupportedInProtocol(ProtocolVersion.TLS11);
    }

    @TlsTest(description = "A client which receives a legacy_session_id_echo " +
            "field that does not match what it sent in the ClientHello MUST " +
            "abort the handshake with an \"illegal_parameter\" alert.")
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void testSessionIdEchoed(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        byte[] sessionId = new byte[32];
        sessionId[0] = (byte) 0xFF;
        sessionId[16] = (byte) 0xFF;
        
        c.setDefaultClientSessionId(sessionId);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new CertificateVerifyMessage(c))
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.executedAsPlanned(i);

            ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertNotNull(AssertMsgs.ServerHelloNotReceived, msg);
            assertArrayEquals("Session ID not echoed", sessionId, msg.getSessionId().getValue());
        });
    }
    
    @TlsTest(description = "A client which receives a legacy_session_id_echo " +
            "field that does not match what it sent in the ClientHello MUST " +
            "abort the handshake with an \"illegal_parameter\" alert.")
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void testShortSessionIdEchoed(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        byte[] sessionId = new byte[8];
        sessionId[0] = (byte) 0xFF;
        
        c.setDefaultClientSessionId(sessionId);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new CertificateVerifyMessage(c))
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.executedAsPlanned(i);

            ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertNotNull(AssertMsgs.ServerHelloNotReceived, msg);
            assertArrayEquals("Session ID not echoed", sessionId, msg.getSessionId().getValue());
        });
    }

    @TlsTest(description = "legacy_compression_method: A single byte which " +
            "MUST have the value 0.")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.MEDIUM)
    public void testCompressionValue(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        runner.execute(workflowTrace, c).validateFinal(i -> {
            assertEquals("invalid compression method",
                    0,
                    i.getWorkflowTrace().getFirstReceivedMessage(ServerHelloMessage.class).getSelectedCompressionMethod().getValue().byteValue()
            );
        });
    }
    
    @TlsTest(description = "As " +
        "with the ServerHello, a HelloRetryRequest MUST NOT contain any " +
        "extensions that were not first offered by the client in its " +
        "ClientHello, with the exception of optionally the \"cookie\" (see " +
        "Section 4.2.2) extension. [...]" + 
        "There MUST NOT be more than one extension of the " +
        "same type in a given extension block. [...]" + 
        "The \"oid_filters\" extension allows servers to provide a set of " +
        "OID/value pairs which it would like the client's certificate to " +
        "match.  This extension, if provided by the server, MUST only be sent " +
        "in the CertificateRequest message. [...]" + 
        "Servers MUST NOT send a post-handshake CertificateRequest to clients " +
        "which do not offer this extension.  Servers MUST NOT send this " +
        "extension. [...]" +
        "Implementations MUST NOT use the Truncated HMAC extension")
    @RFC(number = 8446, section = "4.1.4.  Hello Retry Request, 4.2.  Extensions, 4.2.5. OID Filters, 4.2.6.  Post-Handshake Client Authentication, and D.5.  Security Restrictions Related to Backward Compatibility")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void testProvidedExtensions(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        runner.execute(workflowTrace, config).validateFinal(i -> {
            Validator.executedAsPlanned(i);
            ServerHelloMessage serverHello = i.getWorkflowTrace().getFirstReceivedMessage(ServerHelloMessage.class);
            ClientHelloMessage clientHello = i.getWorkflowTrace().getFirstSendMessage(ClientHelloMessage.class);
            checkForForbiddenExtensions(serverHello);
            checkForUnproposedExtensions(serverHello, clientHello);
            SharedExtensionTests.checkForDuplicateExtensions(serverHello);
        });
    }
    
    public static void checkForUnproposedExtensions(ServerHelloMessage serverHello, ClientHelloMessage clientHello) {
        assertNotNull("ServerHello was not received", serverHello);
        assertNotNull("ClientHello was not provided", clientHello);
        //MUST NOT contain any extensions that were not first 
        //offered by the client in its ClientHello, with the 
        //exception of optionally the "cookie"
        List<ExtensionType> illegalExtensions = new LinkedList<>();
        if(serverHello.getExtensions() != null) {
        for(ExtensionType extension: serverHello.getExtensions().stream().map(ExtensionMessage::getExtensionTypeConstant).toArray(ExtensionType[]::new)) {
            if(!clientHello.containsExtension(extension) && (extension != ExtensionType.COOKIE || !serverHello.isTls13HelloRetryRequest())) {
                illegalExtensions.add(extension);
            }
        }
        assertTrue("Server negotiated the following unproposed extensions: " + illegalExtensions.parallelStream().map(Enum::name).collect(Collectors.joining(",")), illegalExtensions.isEmpty());
        }
    }
    
    public static void checkForForbiddenExtensions(ServerHelloMessage serverHello) {
        assertNotNull("ServerHello was not received", serverHello);
        if(serverHello.getExtensions() != null) {
            //The server MUST NOT send a "psk_key_exchange_modes" extension.
            assertFalse("Server sent a PSK Key Exchange Modes Extension", serverHello.containsExtension(ExtensionType.PSK_KEY_EXCHANGE_MODES));
            //Servers MUST NOT send a post-handshake CertificateRequest to clients
            //which do not offer this extension.  Servers MUST NOT send this
            //extension.
            assertFalse("Server sent a Post Handshake Auth Extension", serverHello.containsExtension(ExtensionType.POST_HANDSHAKE_AUTH));
            //The "oid_filters" extension allows servers to provide a set of
            //OID/value pairs which it would like the client's certificate to
            //match.  This extension, if provided by the server, MUST only be sent
            //in the CertificateRequest message.
            assertFalse("Server sent an OID Filter Extension in Server Hello", serverHello.containsExtension(ExtensionType.OID_FILTERS));
            //Implementations MUST NOT use the Truncated HMAC extension
            assertFalse("Server sent a Truncated HMAC Extension", serverHello.containsExtension(ExtensionType.TRUNCATED_HMAC));
        }
    }
    
    public List<DerivationParameter> getTlsVersionsBelow12(DerivationScope scope) {
        List<DerivationParameter> derivationParameters = new LinkedList<>();
        context.getSiteReport().getVersions().forEach(version -> {
            if(version == ProtocolVersion.TLS10 || version == ProtocolVersion.TLS11) {
                derivationParameters.add(new ProtocolVersionDerivation(version.getValue()));
            }
        });
        return derivationParameters;
    }
}
