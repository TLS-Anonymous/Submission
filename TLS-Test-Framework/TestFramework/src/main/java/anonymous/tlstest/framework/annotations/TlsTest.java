/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.annotations;


import com.fasterxml.jackson.annotation.JsonProperty;
import anonymous.tlstest.framework.coffee4j.model.ModelFromScope;
import anonymous.tlstest.framework.coffee4j.reporter.TlsReporter;
import anonymous.tlstest.framework.coffee4j.reporter.TlsTestsuiteReporter;
import de.rwth.swc.coffee4j.engine.characterization.ben.Ben;
import de.rwth.swc.coffee4j.junit.provider.configuration.characterization.EnableFaultCharacterization;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@TestChooser
@EnableFaultCharacterization(Ben.class)
@ModelFromScope()
@TlsReporter(TlsTestsuiteReporter.class)
public @interface TlsTest {
    @JsonProperty("Description")
    String description() default "";
}
