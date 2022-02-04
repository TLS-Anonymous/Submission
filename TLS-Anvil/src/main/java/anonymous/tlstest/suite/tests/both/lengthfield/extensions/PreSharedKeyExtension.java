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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
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

@ServerTest
@Tag("tls13")
@TlsVersion(supported = ProtocolVersion.TLS13)
@KeyExchange(supported = KeyExchangeType.ALL13)
public class PreSharedKeyExtension extends TlsGenericTest {
    
    public ConditionEvaluationResult supportsPsk() {
        if (context.getSiteReport().getResult(AnalyzedProperty.SUPPORTS_TLS13_PSK) == TestResult.TRUE
                || context.getSiteReport().getResult(AnalyzedProperty.SUPPORTS_TLS13_PSK_DHE) == TestResult.TRUE) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled("Does not support PSK handshakes");
        }
    }
    
    @TlsTest(description = "Send a Pre Shared Key Extension in the Hello Message with a modified length value (-1)")
    @ScopeLimitations(DerivationType.INCLUDE_PSK_EXCHANGE_MODES_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MethodCondition(method = "supportsPsk")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void preSharedKeyExtensionLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupPreSharedKeyLengthFieldTest(argumentAccessor, runner);
        PreSharedKeyExtensionMessage pskExtension = getPSKExtension(workflowTrace);
        pskExtension.setExtensionLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
    
    @TlsTest(description = "Send a Pre Shared Key Extension in the Hello Message with a modified length value (-1)")
    @ScopeLimitations(DerivationType.INCLUDE_PSK_EXCHANGE_MODES_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MethodCondition(method = "supportsPsk")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void preSharedKeyExtensionIdentityListLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupPreSharedKeyLengthFieldTest(argumentAccessor, runner);
        PreSharedKeyExtensionMessage pskExtension = getPSKExtension(workflowTrace);
        pskExtension.setIdentityListLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
        
    @TlsTest(description = "Send a Pre Shared Key Extension in the Hello Message with a modified length value (-1)")
    @ScopeLimitations(DerivationType.INCLUDE_PSK_EXCHANGE_MODES_EXTENSION)
    @ModelFromScope(baseModel = ModelType.LENGTHFIELD)
    @MethodCondition(method = "supportsPsk")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void preSharedKeyExtensionBinderListLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupPreSharedKeyLengthFieldTest(argumentAccessor, runner);
        PreSharedKeyExtensionMessage pskExtension = getPSKExtension(workflowTrace);
        pskExtension.setBinderListLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(super::validateLengthTest);
    }
    
    private WorkflowTrace setupPreSharedKeyLengthFieldTest(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = context.getConfig().createTls13Config();
        config.setAddPSKKeyExchangeModesExtension(true);
        config.setAddPreSharedKeyExtension(true);
        //RFC 8446: Servers SHOULD NOT attempt to validate multiple binders;
        //rather, they SHOULD select a single PSK and validate solely the
        //binder that corresponds to that PSK.
        config.setLimitPsksToOne(Boolean.TRUE);
        adjustPreSharedKeyModes(config);
        prepareConfig(config, argumentAccessor, runner);
        return runner.generateWorkflowTrace(WorkflowTraceType.FULL_TLS13_PSK);
    }
    
    private PreSharedKeyExtensionMessage getPSKExtension(WorkflowTrace workflowTrace) {
        ClientHelloMessage secondClientHello = (ClientHelloMessage) WorkflowTraceUtil.getLastSendMessage(HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        return (PreSharedKeyExtensionMessage) secondClientHello.getExtension(PreSharedKeyExtensionMessage.class);
    }
}
