package pt.unl.fct.shp.crypto;

import pt.unl.fct.common.crypto.CryptoUtils;
import pt.unl.fct.common.crypto.DigitalSignature;

import java.security.*;

public class ShpDigitalSignature implements DigitalSignature {

    private static final Signature ECDSA_SIGNATURE;
    private static final Signature ECDSA_VERIFIER;

    static {
        try {
            ECDSA_SIGNATURE = Signature.getInstance("SHA256withECDSA", "BC");
            ECDSA_VERIFIER = Signature.getInstance("SHA256withECDSA", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public ShpDigitalSignature() {
        // empty
    }

    @Override
    public byte[] sign(PrivateKey privateKey, byte[] data) throws InvalidKeyException, SignatureException {
        ECDSA_SIGNATURE.initSign(privateKey, CryptoUtils.SECURE_RANDOM);
        ECDSA_SIGNATURE.update(data);
        return ECDSA_SIGNATURE.sign();
    }

    @Override
    public boolean verify(PublicKey publicKey, byte[] data, byte[] signature) throws InvalidKeyException, SignatureException {
        ECDSA_VERIFIER.initVerify(publicKey);
        ECDSA_VERIFIER.update(data);
        return ECDSA_VERIFIER.verify(signature);
    }

    @Override
    public int getSignatureLength() {
        return ECDSA_SIGNATURE.getAlgorithm().length();
    }
}
