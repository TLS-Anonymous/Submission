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

import anonymous.tlstest.framework.model.ModelType;
import de.rwth.swc.coffee4j.junit.provider.model.ModelSource;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 
 *  This is an extended copy of the ModelFromMethod of Coffee4j.
 */
@Inherited
@Target({ElementType.ANNOTATION_TYPE, ElementType.FIELD, ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@ModelSource(ScopeBasedProvider.class)
public @interface ModelFromScope {
    String name() default "TlsTest";
    ModelType baseModel() default ModelType.GENERIC;
}
