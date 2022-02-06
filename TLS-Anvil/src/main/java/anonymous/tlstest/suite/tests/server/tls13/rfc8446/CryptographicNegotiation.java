/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ScopeLimitations;
import anonymous.tlstest.framework.annotations.ServerTest;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.constants.TestResult;
import anonymous.tlstest.framework.execution.AnnotatedState;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.testClasses.Tls13Test;

import org.junit.jupiter.api.Tag;

import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 8446, section = "4.1.1 Cryptographic Negotiation")
public class CryptographicNegotiation extends Tls13Test {

    @TlsTest(description = "If no " +
        "common cryptographic parameters can be negotiated, the server MUST " +
        "abort the handshake with an appropriate alert.[...] " +
        "If there is no overlap between the received " +
        "\"supported_groups\" and the groups supported by the server, then the " +
        "server MUST abort the handshake with a \"handshake_failure\" or an " +
        "\"insufficient_security\" alert.")
    @RFC(number = 8446, section = "2.1.  Incorrect DHE Share and 4.1.1 Cryptographic Negotiation")
    @ScopeLimitations({DerivationType.INCLUDE_GREASE_NAMED_GROUPS, DerivationType.NAMED_GROUP})
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    //Todo: add 'Groups' to method name
    public void noOverlappingParameters(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage chm = new ClientHelloMessage(config);
        
        //set up an undefined group and key share
        EllipticCurvesExtensionMessage eccExtension = chm.getExtension(EllipticCurvesExtensionMessage.class);
        eccExtension.setSupportedGroups(Modifiable.explicit(NamedGroup.GREASE_00.getValue()));
        KeyShareExtensionMessage keyShareExtension = chm.getExtension(KeyShareExtensionMessage.class);
        keyShareExtension.setKeyShareListBytes(Modifiable.explicit(new byte[] {0x0A, 0x0A, 0x00, 0x02, 0x12, 0x34}));
        
        WorkflowTrace trace = buildWorkflowTrace(chm);

        runner.execute(trace, config).validateFinal(i -> {
            validateResult(i, trace);
        });
    }

    @TlsTest(description = "If the server is unable to negotiate a supported set of parameters " +
            "(i.e., there is no overlap between the client and server parameters), it MUST abort " +
            "the handshake with either a \"handshake_failure\" or \"insufficient_security\" fatal alert (see Section 6).")
    @ScopeLimitations({DerivationType.INCLUDE_GREASE_CIPHER_SUITES, DerivationType.CIPHERSUITE})
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void noOverlappingParametersCipherSuite(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage chm = new ClientHelloMessage(config);
        chm.setCipherSuites(Modifiable.explicit(CipherSuite.GREASE_00.getByteValue()));

        WorkflowTrace trace = buildWorkflowTrace(chm);

        runner.execute(trace, config).validateFinal(i -> {
            validateResult(i, trace);
        });
    }
    
    private void validateResult(AnnotatedState i, WorkflowTrace trace) {
        Validator.receivedFatalAlert(i);
        AlertMessage alert = trace.getFirstReceivedMessage(AlertMessage.class);
        if (alert == null) {
            return;
        }
        
        //todo add testAlertDescription for multiple allowed alerts
        //also required for FFDHE tests
        AlertDescription description = AlertDescription.getAlertDescription(alert.getDescription().getValue());
        if(description != AlertDescription.HANDSHAKE_FAILURE && description != AlertDescription.INSUFFICIENT_SECURITY) {
            i.setResult(TestResult.PARTIALLY_SUCCEEDED);
            i.addAdditionalResultInfo("Alert was not Handshake Failure or Insufficient Security");
        }
    }
    
    private WorkflowTrace buildWorkflowTrace(ClientHelloMessage chm) {
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                new SendAction(chm),
                new ReceiveAction(new AlertMessage())
        );
        return trace;
    }
}
