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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
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
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.model.ModelType;
import anonymous.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@Tag("tls13")
@ServerTest
@TlsVersion(supported = ProtocolVersion.TLS13)
@KeyExchange(supported = KeyExchangeType.ALL13)
public class PSKKeyExchangeModesExtension extends TlsGenericTest {
    
    public ConditionEvaluationResult contentCanBeTested() {
        if(context.getSiteReport().getResult(AnalyzedProperty.SUPPORTS_TLS13_SESSION_TICKETS) == TestResult.TRUE) {
            return ConditionEvaluationResult.enabled("The Extension content can be tested");
        }
        return ConditionEvaluationResult.disabled("Server does not issue Session Tickets and might ignore the extension");
    }
    
    @TlsTest(description = "Send a Pre Shared Key Exchange Modes Extension in the Hello Message with a modified length value (-1)")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @ScopeLimitations(DerivationType.INCLUDE_PSK_EXCHANGE_MODES_EXTENSION)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void pskKeyExchangeModesExtensionLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddPSKKeyExchangeModesExtension(true);
        genericExtensionLengthTest(runner, argumentAccessor, config, PSKKeyExchangeModesExtensionMessage.class);
    }
    
    @TlsTest(description = "Send a Pre Shared Key Exchange Modes Extension in the Hello Message with a modified length value (-1)")
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @ScopeLimitations(DerivationType.INCLUDE_PSK_EXCHANGE_MODES_EXTENSION)
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    @MethodCondition(method="contentCanBeTested")
    public void pskKeyExchangeModesExtensionListLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddPSKKeyExchangeModesExtension(true);
        WorkflowTrace workflowTrace = setupLengthFieldTestForConfig(config, runner, argumentAccessor);
        PSKKeyExchangeModesExtensionMessage keyExchangeModes = getTargetedExtension(PSKKeyExchangeModesExtensionMessage.class, workflowTrace);
        keyExchangeModes.setKeyExchangeModesListLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);        
    }
}
