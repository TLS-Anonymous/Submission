/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.framework.annotations.methodCondition;

import anonymous.tlstest.framework.annotations.MethodCondition;
import anonymous.tlstest.framework.junitExtensions.MethodConditionExtension;
import anonymous.tlstest.framework.utils.ConditionTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static org.junit.Assert.assertTrue;


public class MethodConditionAnnotationOtherClass {

    @RegisterExtension
    static ConditionTest ext = new ConditionTest(MethodConditionExtension.class);

    @Test
    @MethodCondition(clazz = OtherClassCondition.class, method="publicTest")
    public void execute_validPublicMethod() {
        assertTrue(OtherClassCondition.instance.publicTest);
    }

    @Test
    @MethodCondition(clazz = OtherClassCondition.class, method="privateTest")
    public void execute_validPrivateMethod() {
        assertTrue(OtherClassCondition.instance.privateTest);
    }

    @Test
    public void execute_noAnnotation() { }

}
