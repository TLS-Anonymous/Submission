/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package anonymous.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ServerTest;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.annotations.categories.InteroperabilityCategory;
import anonymous.tlstest.framework.constants.AssertMsgs;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.testClasses.Tls13Test;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 8446, section = "4.3.1  Encrypted Extensions")
public class EncryptedExtensions extends Tls13Test {
    
    public ConditionEvaluationResult sniActive() {
        Config c = this.getConfig();
        if (c.isAddServerNameIndicationExtension()) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("SNI is disabled");
    }
    
    @TlsTest(description = "The client MUST check EncryptedExtensions for the " +
            "presence of any forbidden extensions and if any are found MUST abort " +
            "the handshake with an \"illegal_parameter\" alert.")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void includedInvalidExtensions(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            EncryptedExtensionsMessage encExt = trace.getFirstReceivedMessage(EncryptedExtensionsMessage.class);
            assertNotNull(AssertMsgs.EncExtensionsNotReceived, encExt);
            
            for(ExtensionMessage ext : encExt.getExtensions()) {
                assertTrue("EncryptedExtensions contained a forbidden extension: " +ExtensionType.getExtensionType(ext.getExtensionType().getValue()),ExtensionType.allowedInEncryptedExtensions(ExtensionType.getExtensionType(ext.getExtensionType().getValue())));
            }
        });
    }

}
