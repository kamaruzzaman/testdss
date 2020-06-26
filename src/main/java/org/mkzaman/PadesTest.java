package org.mkzaman;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

public class PadesTest extends PKIFactoryAccess {
    private DSSDocument documentToSign;
    private PAdESSignatureParameters parameters;
    private PAdESService service;

    public static void main(String[] args) {

        // https://github.com/esig/dss/blob/master/dss-pades/src/test/java/eu/europa/esig/dss/pades/signature/suite/PAdESAllSelfSignedCertsTest.java
        PadesTest padesTest = new PadesTest();
        padesTest.testSign();
    }

    private void testSign() {
        this.documentToSign = new InMemoryDocument(PadesTest.class.getResourceAsStream("/sample.pdf"));

        parameters = new PAdESSignatureParameters();
// We choose the level of the signature (-B, -T, -LT, -LTA).
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
// We set the digest algorithm to use with the signature algorithm. You must use the
// same parameter when you invoke the method sign on the token. The default value is
// SHA256
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

// We set the signing certificate
        parameters.setSigningCertificate(getSigningCert());
// We set the certificate chain
        parameters.setCertificateChain(getCertificateChain());

// Create common certificate verifier
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
// Create PAdESService for signature
        service = new PAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getSelfSignedTsa());
// Get the SignedInfo segment that need to be signed.
        DSSDocument signedDocument = sign();
    }

    private DSSDocument sign() {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, parameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, parameters.getDigestAlgorithm(), getPrivateKeyEntry());
        return service.signDocument(documentToSign, parameters, signatureValue);
    }

    @Override
    protected String getSigningAlias() {
        return SELF_SIGNED_USER;
    }
}
