/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.both.lengthfield.extensions;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import anonymous.tlstest.framework.annotations.KeyExchange;
import anonymous.tlstest.framework.annotations.ServerTest;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.TlsVersion;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.MessageStructureCategory;
import anonymous.tlstest.framework.coffee4j.model.ModelFromScope;
import anonymous.tlstest.framework.constants.KeyExchangeType;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.ModelType;
import anonymous.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class SignatureAndHashAlgorithmsExtension extends TlsGenericTest {

    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @TlsTest(description = "Send a Signature And Hash Algorithms Extension in the Hello Message with a modified length value (-1)")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void signatureAndHashAlgorithmsExtensionLengthTLS12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        genericExtensionLengthTest(runner, argumentAccessor, config, SignatureAndHashAlgorithmsExtensionMessage.class);
    }
    
    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @TlsTest(description = "Send a Signature And Hash Algorithms Extension in the Hello Message with a modified length value (-1)")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void signatureAndHashAlgorithmsExtensionLengthTLS13(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        genericExtensionLengthTest(runner, argumentAccessor, config, SignatureAndHashAlgorithmsExtensionMessage.class);
    }
    
    
    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @TlsTest(description = "Send a Signature And Hash Algorithms Extension in the Hello Message with a modified algorithm list length value (-1)")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void signatureAndHashAlgorithmsListLengthTLS12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        signatureAndHashAlgorithmsListLengthTest(config, runner, argumentAccessor);
    }
    
    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @TlsTest(description = "Send a Signature And Hash Algorithms Extension in the Hello Message with a modified algorithm list length value (-1)")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void signatureAndHashAlgorithmsListLengthTLS13(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        signatureAndHashAlgorithmsListLengthTest(config, runner, argumentAccessor);
    }
    
    
    private void signatureAndHashAlgorithmsListLengthTest(Config versionBasedConfig, WorkflowRunner runner, ArgumentsAccessor argumentAccessor) {
        versionBasedConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        WorkflowTrace workflowTrace = setupLengthFieldTestForConfig(versionBasedConfig, runner, argumentAccessor);
        SignatureAndHashAlgorithmsExtensionMessage sigAndHashAlgorithmsExtension = getTargetedExtension(SignatureAndHashAlgorithmsExtensionMessage.class, workflowTrace);
        sigAndHashAlgorithmsExtension.setSignatureAndHashAlgorithmsLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
}
