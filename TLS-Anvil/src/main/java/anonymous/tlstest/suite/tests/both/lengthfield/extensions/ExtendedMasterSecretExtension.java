/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.both.lengthfield.extensions;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import anonymous.tlstest.framework.TestContext;
import anonymous.tlstest.framework.annotations.KeyExchange;
import anonymous.tlstest.framework.annotations.MethodCondition;
import anonymous.tlstest.framework.annotations.ScopeLimitations;
import anonymous.tlstest.framework.annotations.ServerTest;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.TlsVersion;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.MessageStructureCategory;
import anonymous.tlstest.framework.coffee4j.model.ModelFromScope;
import anonymous.tlstest.framework.constants.KeyExchangeType;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.constants.TestEndpointType;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.model.ModelType;
import anonymous.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class ExtendedMasterSecretExtension extends TlsGenericTest {
    
    public ConditionEvaluationResult targetCanBeTested() {
        if(TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.SERVER ||
                TestContext.getInstance().getSiteReport().getReceivedClientHello().containsExtension(ExtensionType.EXTENDED_MASTER_SECRET)) {
            return ConditionEvaluationResult.enabled("The Extension can be tested");
        }
        return ConditionEvaluationResult.disabled("Target is not a server and did not include the required Extension in Client Hello");
    }
    
    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @TlsTest(description = "Send an Extended Master Secret Extension in the Hello Message with a modified length value (+1)")
    @ScopeLimitations(DerivationType.INCLUDE_EXTENDED_MASTER_SECRET_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MethodCondition(method = "targetCanBeTested")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void extendedMasterSecretExtensionLengthTLS12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        config.setAddExtendedMasterSecretExtension(true);
        emptyExtensionLengthTest(runner, argumentAccessor, config, ExtendedMasterSecretExtensionMessage.class);
    }
    
    @Tag("tls13")
    @ServerTest
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @TlsTest(description = "Send an Extended Master Secret Extension in the Hello Message with a modified length value (+1)")
    @ScopeLimitations(DerivationType.INCLUDE_EXTENDED_MASTER_SECRET_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void extendedMasterSecretExtensionLengthTLS13(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddExtendedMasterSecretExtension(true);
        emptyExtensionLengthTest(runner, argumentAccessor, config, ExtendedMasterSecretExtensionMessage.class);
    }
}
