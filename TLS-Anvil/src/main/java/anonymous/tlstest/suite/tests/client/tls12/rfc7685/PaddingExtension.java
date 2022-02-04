/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.client.tls12.rfc7685;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.MethodCondition;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.TestDescription;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.constants.AssertMsgs;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@RFC(number = 7685, section = "3")
@ClientTest
public class PaddingExtension extends Tls12Test {

    public ConditionEvaluationResult offeredExtension() {
        if(context.getReceivedClientHelloMessage().containsExtension(ExtensionType.PADDING)) {
            return ConditionEvaluationResult.enabled("The Extension can be evaluated");
        }
        return ConditionEvaluationResult.disabled("Extension has not been offered and can not be evaluated");
    }
    
    @Test
    @TestDescription("The client MUST fill the padding extension completely with zero "
            + "bytes, although the padding extension_data field may be empty.")
    @ComplianceCategory(SeverityLevel.LOW)
    @HandshakeCategory(SeverityLevel.LOW)
    @MethodCondition(method="offeredExtension")
    public void paddingWithNonZero() {
        ClientHelloMessage msg = context.getReceivedClientHelloMessage();
        assertNotNull(AssertMsgs.ClientHelloNotReceived, msg);

        PaddingExtensionMessage paddingExt = msg.getExtension(PaddingExtensionMessage.class);

        byte[] receivedPaddingExt = paddingExt.getPaddingBytes().getValue();
        byte[] expected = new byte[receivedPaddingExt.length];
        assertArrayEquals("Padding extension padding bytes not zero", expected, receivedPaddingExt);

    }

}
