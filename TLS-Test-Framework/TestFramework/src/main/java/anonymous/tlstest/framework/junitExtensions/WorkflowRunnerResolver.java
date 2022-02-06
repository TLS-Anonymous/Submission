/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.junitExtensions;

import anonymous.tlstest.framework.execution.WorkflowRunner;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;

/**
 * Creates a WorkflowRunner object that is passed to a test method that has
 * specified a WorkflowRunner argument.
 */
public class WorkflowRunnerResolver implements ParameterResolver {
    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
        return parameterContext.getParameter().getType().equals(WorkflowRunner.class);
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
        if (!extensionContext.getTestMethod().isPresent()) {
            return null;
        }

        return new WorkflowRunner(extensionContext);
    }
}
