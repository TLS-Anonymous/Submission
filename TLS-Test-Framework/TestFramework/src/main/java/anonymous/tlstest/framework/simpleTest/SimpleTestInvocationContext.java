/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.simpleTest;

import anonymous.tlstest.framework.model.derivationParameter.DerivationParameter;
import anonymous.tlstest.framework.coffee4j.junit.TlsTestCombinatorialTestNameFormatter;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.extension.Extension;
import org.junit.jupiter.api.extension.TestTemplateInvocationContext;

/**
 *
 */
public class SimpleTestInvocationContext implements TestTemplateInvocationContext {
    
    private final TlsTestCombinatorialTestNameFormatter nameFormatter;
    
    private final List<DerivationParameter> testInput;

    public SimpleTestInvocationContext(DerivationParameter testInput) {
        this();
        this.testInput.add(testInput);
    } 
    
    public SimpleTestInvocationContext() {
        this.testInput = new LinkedList<>();
        this.nameFormatter = new TlsTestCombinatorialTestNameFormatter("[{index}] {combination}");
    }
    
    @Override
    public String getDisplayName(int invocationIndex) {
        return nameFormatter.format(invocationIndex, testInput);
        
    }
    
    @Override
    public List<Extension> getAdditionalExtensions() {
        return Arrays.asList(new SimpleTestParameterResolver(testInput), new SimpleTestExecutionCallback());
    }
}
