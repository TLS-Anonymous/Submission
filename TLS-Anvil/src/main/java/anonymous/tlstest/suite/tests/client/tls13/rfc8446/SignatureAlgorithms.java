/**
 * TLS-Anvil - A testsuite for the TLS protocol
 *
 * Copyright 2022 Anonymous
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import anonymous.tlstest.framework.Validator;
import anonymous.tlstest.framework.annotations.ClientTest;
import anonymous.tlstest.framework.annotations.DynamicValueConstraints;
import anonymous.tlstest.framework.annotations.ExplicitModelingConstraints;
import anonymous.tlstest.framework.annotations.KeyExchange;
import anonymous.tlstest.framework.annotations.MethodCondition;
import anonymous.tlstest.framework.annotations.RFC;
import anonymous.tlstest.framework.annotations.TestDescription;
import anonymous.tlstest.framework.annotations.TlsTest;
import anonymous.tlstest.framework.annotations.categories.ComplianceCategory;
import anonymous.tlstest.framework.annotations.categories.HandshakeCategory;
import anonymous.tlstest.framework.coffee4j.model.ModelFromScope;
import anonymous.tlstest.framework.constants.KeyExchangeType;
import anonymous.tlstest.framework.constants.SeverityLevel;
import anonymous.tlstest.framework.execution.WorkflowRunner;
import anonymous.tlstest.framework.model.DerivationScope;
import anonymous.tlstest.framework.model.DerivationType;
import anonymous.tlstest.framework.model.ModelType;
import anonymous.tlstest.framework.model.constraint.ConditionalConstraint;
import anonymous.tlstest.framework.model.derivationParameter.CertificateDerivation;
import anonymous.tlstest.framework.model.derivationParameter.SigAndHashDerivation;
import anonymous.tlstest.framework.testClasses.Tls13Test;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import org.junit.jupiter.api.Test;

@RFC(number = 8446, section = "4.2.3. Signature Algorithms")
@ClientTest
public class SignatureAlgorithms extends Tls13Test {
    
    public ConditionEvaluationResult supportsTls12() {
        if (context.getSiteReport().getVersions().contains(ProtocolVersion.TLS12)) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("TLS 1.2 is not supported by the server.");
    }
    
    @TlsTest(description = "Note that TLS 1.2 defines this extension differently.  TLS 1.3 " +
        "implementations willing to negotiate TLS 1.2 MUST behave in " +
        "accordance with the requirements of [RFC5246] when negotiating that " +
        "version. In particular:[...]" + 
        "ECDSA signature schemes align with TLS 1.2's ECDSA hash/signature " +
        "pairs.  However, the old semantics did not constrain the signing " +
        "curve.  If TLS 1.2 is negotiated, implementations MUST be prepared " +
        "to accept a signature that uses any curve that they advertised in " +
        "the \"supported_groups\" extension.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @HandshakeCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ExplicitModelingConstraints(affectedTypes = DerivationType.SIG_HASH_ALGORIHTM, methods = "getMixedEccHashLengthPairs")
    @DynamicValueConstraints(affectedTypes = {DerivationType.CIPHERSUITE, DerivationType.CERTIFICATE, DerivationType.SIG_HASH_ALGORIHTM}, methods = {"isEcdsaCipherSuite", "isApplicableEcdsaCert", "isTls13SigHash"})
    @Tag("new")
    public void acceptsMixedCurveHashLengthInTls12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        runner.execute(workflowTrace, config).validateFinal(Validator::executedAsPlanned);
    }
    
    @TlsTest(description = "Note that TLS 1.2 defines this extension differently.  TLS 1.3 " +
        "implementations willing to negotiate TLS 1.2 MUST behave in " +
        "accordance with the requirements of [RFC5246] when negotiating that " +
        "version. In particular:[...]" + 
        "Implementations that advertise support for RSASSA-PSS (which is " +
        "mandatory in TLS 1.3) MUST be prepared to accept a signature using " +
        "that scheme even when TLS 1.2 is negotiated.  In TLS 1.2, " +
        "RSASSA-PSS is used with RSA cipher suites.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @HandshakeCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @DynamicValueConstraints(affectedTypes = {DerivationType.CIPHERSUITE, DerivationType.SIG_HASH_ALGORIHTM}, methods = {"isRsaSignatureCipherSuite", "isRsaPssAlgorithm"})
    @Tag("new")
    public void supportsRsaPssInTls12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        runner.execute(workflowTrace, config).validateFinal(Validator::executedAsPlanned);
    }
    
    
    @Test
    @TestDescription("Note that TLS 1.2 defines this extension differently.  TLS 1.3 " +
        "implementations willing to negotiate TLS 1.2 MUST behave in " +
        "accordance with the requirements of [RFC5246] when negotiating that " +
        "version. In particular:[...]" + 
        "In TLS 1.2, the extension contained hash/signature pairs.  The " +
        "pairs are encoded in two octets, so SignatureScheme values have " +
        "been allocated to align with TLS 1.2's encoding.  Some legacy " +
        "pairs are left unallocated.  These algorithms are deprecated as of " +
        "TLS 1.3.  They MUST NOT be offered or negotiated by any " +
        "implementation.  In particular, MD5 [SLOTH], SHA-224, and DSA " +
        "MUST NOT be used.")
    @Tag("new")
    public void noDeprecatedAlgorithmsOffered() {
        if(context.getSiteReport().getSupportedSignatureAndHashAlgorithms() != null) {
            List<SignatureAndHashAlgorithm> deprecatedOffered = new LinkedList();
            context.getSiteReport().getSupportedSignatureAndHashAlgorithms().forEach(algorithm -> {
                if(algorithm.getSignatureAlgorithm() == SignatureAlgorithm.DSA || algorithm.getHashAlgorithm() == HashAlgorithm.MD5 || algorithm.getHashAlgorithm() == HashAlgorithm.SHA224 || algorithm.getHashAlgorithm() == HashAlgorithm.SHA1) {
                    deprecatedOffered.add(algorithm);
                }
            });
            
            assertTrue("Client offered deprecated algorithms: " + deprecatedOffered.stream().map(Object::toString).collect(Collectors.joining(",")), deprecatedOffered.isEmpty());
        }
    }
    
    public boolean isTls13SigHash(SignatureAndHashAlgorithm algorithmPair) {
        return algorithmPair != null && algorithmPair.suitedForSigningTls13Messages();
    }
    
    public boolean isEcdsaCipherSuite(CipherSuite cipherSuite) {
        return AlgorithmResolver.getCertificateKeyType(cipherSuite) == CertificateKeyType.ECDSA;
    }
    
    public boolean isApplicableEcdsaCert(CertificateKeyPair keyPair) {
        return (keyPair.getCertPublicKeyType() == CertificateKeyType.ECDSA || keyPair.getCertPublicKeyType() == CertificateKeyType.ECDH) && (keyPair.getPublicKeyGroup() == NamedGroup.SECP256R1 || keyPair.getPublicKeyGroup() == NamedGroup.SECP384R1 || keyPair.getPublicKeyGroup() == NamedGroup.SECP521R1);
    }
    
    public boolean isRsaSignatureCipherSuite(CipherSuite cipherSuite) {
        return cipherSuite.isEphemeral() && AlgorithmResolver.getCertificateKeyType(cipherSuite) != null && AlgorithmResolver.getCertificateKeyType(cipherSuite) == CertificateKeyType.RSA;
    }
    
    public boolean isRsaPssAlgorithm(SignatureAndHashAlgorithm algorithmPair) {
        return algorithmPair != null && algorithmPair.getSignatureAlgorithm().name().contains("PSS");
    }
    
    
    public List<ConditionalConstraint> getMixedEccHashLengthPairs(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();
        condConstraints.addAll(SigAndHashDerivation.getSharedDefaultConditionalConstraints(scope));
        condConstraints.addAll(SigAndHashDerivation.getDefaultPreTls13Constraints(scope));
        condConstraints.add(getHashSizeMustNotMatchEcdsaPkSizeConstraint());
        return condConstraints;
    }
    
    private ConditionalConstraint getHashSizeMustNotMatchEcdsaPkSizeConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CERTIFICATE);

        //TLS 1.3 specifies explicit curves for hash functions in ECDSA
        //e.g ecdsa_secp256r1_sha256
        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(DerivationType.SIG_HASH_ALGORIHTM.name(), DerivationType.CERTIFICATE.name()).by((SigAndHashDerivation sigAndHashDerivation, CertificateDerivation certificateDerivation) -> {
            if (sigAndHashDerivation.getSelectedValue() != null) {
                CertificateKeyPair certKeyPair = certificateDerivation.getSelectedValue();
                HashAlgorithm hashAlgo = sigAndHashDerivation.getSelectedValue().getHashAlgorithm();

                if ((certKeyPair.getPublicKeyGroup() == NamedGroup.SECP256R1 && hashAlgo != HashAlgorithm.SHA256)
                        || (certKeyPair.getPublicKeyGroup() == NamedGroup.SECP384R1 && hashAlgo != HashAlgorithm.SHA384)
                        || (certKeyPair.getPublicKeyGroup() == NamedGroup.SECP521R1 && hashAlgo != HashAlgorithm.SHA512)) {
                    return true;
                }
            }
            return false;
        }));
    }
}
