package org.mkzaman.testdss;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

import java.io.IOException;

public class PadesTest extends PKIFactoryAccess {
    private DSSDocument documentToSign;
    private PAdESSignatureParameters parameters;
    private PAdESService service;
    private CommonCertificateVerifier commonCertificateVerifier;

    public static void main(String[] args) {

        // https://github.com/esig/dss/blob/master/dss-pades/src/test/java/eu/europa/esig/dss/pades/signature/suite/PAdESAllSelfSignedCertsTest.java
        PadesTest padesTest = new PadesTest();
        padesTest.testSign();
    }

    private void testSign() {
        init();
        DSSDocument signedDocument = sign();
        try {
            signedDocument.save("./signed.pdf");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void init() {
        this.documentToSign = new InMemoryDocument(PadesTest.class.getResourceAsStream("/sample.pdf"));

        parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSigningCertificate(getSigningCert());
        // parameters.setCertificateChain(getCertificateChain());
        commonCertificateVerifier = new CommonCertificateVerifier();
        service = new PAdESService(getCompleteCertificateVerifier());
        // service.setTspSource(getSelfSignedTsa());
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
