/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package anonymous.tlstest.framework.coffee4j.model;

import anonymous.tlstest.framework.TestContext;
import anonymous.tlstest.framework.model.DerivationScope;
import anonymous.tlstest.framework.model.ParameterModelFactory;
import de.rwth.swc.coffee4j.junit.provider.model.ModelProvider;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.support.AnnotationConsumer;
import org.junit.platform.commons.JUnitException;

/**
 *
 * A modified copy of the ModelFromMethodProvider from Coffee4j.
 */
public class ScopeBasedProvider implements ModelProvider, AnnotationConsumer<ModelFromScope> {
    
    private ModelFromScope modelFromScope;
    
    @Override
    public void accept(ModelFromScope modelFromScope) {
        this.modelFromScope = modelFromScope;
    }
    
    @Override
    public InputParameterModel provide(ExtensionContext extensionContext) {
        DerivationScope derivationScope = new DerivationScope(extensionContext, modelFromScope);
        final Object providedObject = ParameterModelFactory.generateModel(derivationScope, TestContext.getInstance());
        return toInputParameterModel(providedObject);
    }
    
    private static InputParameterModel toInputParameterModel(Object object) {
        if (object instanceof InputParameterModel) {
            return (InputParameterModel) object;
        } else if (object instanceof InputParameterModel.Builder) {
            return ((InputParameterModel.Builder) object).build();
        } else {
            throw new JUnitException("The given method must either return an " + InputParameterModel.class.getName() + " or an " + InputParameterModel.Builder.class.getName() + ". Instead a " + object.getClass().getName() + " was returned");
        }
    }
 
}
