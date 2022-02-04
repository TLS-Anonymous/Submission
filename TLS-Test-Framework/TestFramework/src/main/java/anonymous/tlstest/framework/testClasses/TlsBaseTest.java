/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.testClasses;

import anonymous.tlstest.framework.TestContext;
import anonymous.tlstest.framework.junitExtensions.EndpointCondition;
import anonymous.tlstest.framework.junitExtensions.EnforcedSenderRestrictionConditionExtension;
import anonymous.tlstest.framework.junitExtensions.ExtensionContextResolver;
import anonymous.tlstest.framework.junitExtensions.KexCondition;
import anonymous.tlstest.framework.junitExtensions.MethodConditionExtension;
import anonymous.tlstest.framework.junitExtensions.TestWatcher;
import anonymous.tlstest.framework.junitExtensions.TlsVersionCondition;
import anonymous.tlstest.framework.junitExtensions.ValueConstraintsConditionExtension;
import anonymous.tlstest.framework.junitExtensions.WorkflowRunnerResolver;
import anonymous.tlstest.framework.model.DerivationContainer;
import anonymous.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import anonymous.tlstest.framework.execution.WorkflowRunner;

import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ExtendWith({
        TestWatcher.class,
        EndpointCondition.class,
        TlsVersionCondition.class,
        KexCondition.class,
        MethodConditionExtension.class,
        EnforcedSenderRestrictionConditionExtension.class,
        ValueConstraintsConditionExtension.class,
        ExtensionContextResolver.class,
        WorkflowRunnerResolver.class
})
public abstract class TlsBaseTest {
    protected static final Logger LOGGER = LogManager.getLogger();

    protected TestContext context;
    
    protected DerivationContainer derivationContainer;
    
    protected ExtensionContext extensionContext;
    
    @BeforeEach
    public void setExtensionContext(ExtensionContext extensionContext) {
        this.extensionContext = extensionContext;
    }
    
    public Config getPreparedConfig(ArgumentsAccessor argAccessor, WorkflowRunner runner) {
        Config toPrepare = getConfig();
        return prepareConfig(toPrepare, argAccessor, runner);
    }
    
    public Config prepareConfig(Config config, ArgumentsAccessor argAccessor, WorkflowRunner runner) {
        derivationContainer = new DerivationContainer(argAccessor.toList(), new DerivationScope(extensionContext));
        derivationContainer.applyToConfig(config, context);
        runner.setPreparedConfig(config);
        runner.setDerivationContainer(derivationContainer);
        return config;
    }
    
    public void adjustPreSharedKeyModes(Config config) {
        if(context.getSiteReport().getResult(AnalyzedProperty.SUPPORTS_TLS13_PSK_DHE) == TestResult.TRUE &&
                context.getSiteReport().getResult(AnalyzedProperty.SUPPORTS_TLS13_PSK) == TestResult.FALSE) {
            config.setPSKKeyExchangeModes(Arrays.asList(PskKeyExchangeMode.PSK_DHE_KE));
        }
    }
    
    public TlsBaseTest() {
        this.context = TestContext.getInstance();
    }

    public void setTestContext(TestContext testCotext) {
        this.context = testCotext;
    }

    public TestContext getTestContext() {
        return context;
    }
    
    public abstract Config getConfig();
}

