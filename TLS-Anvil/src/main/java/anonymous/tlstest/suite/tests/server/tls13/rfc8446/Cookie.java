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
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.EnforcedSenderRestriction;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.ServerTest;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.AlertCategory;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 8446, section = "4.2.2 Cookie")
public class Cookie extends Tls13Test {

    @TlsTest(description = "Clients MUST NOT use cookies in their initial ClientHello in subsequent connections.")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    @EnforcedSenderRestriction
    public void clientHelloWithUnsolicitedCookieExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        clientHello.setExtensionBytes(Modifiable.insert(new byte[]{0x00, 44, 0x00, 0x03, 0x00, 0x01, 0x02}, 0));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                new SendAction(clientHello),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, config).validateFinal(Validator::receivedFatalAlert);

    }
}
