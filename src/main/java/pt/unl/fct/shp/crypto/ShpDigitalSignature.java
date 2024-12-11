package pt.unl.fct.shp.crypto;

import pt.unl.fct.common.crypto.DigitalSignature;

import java.security.*;

public class ShpDigitalSignature implements DigitalSignature {

    private final Signature ecdsaSignature;

    public ShpDigitalSignature() {
        try {
            ecdsaSignature = Signature.getInstance("SHA256withECDSA", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] sign(PrivateKey privateKey, byte[] data) throws InvalidKeyException, SignatureException {
        ecdsaSignature.initSign(privateKey);
        ecdsaSignature.update(data);
        return ecdsaSignature.sign();
    }

    @Override
    public boolean verify(PublicKey publicKey, byte[] data, byte[] signature) throws InvalidKeyException, SignatureException {
        ecdsaSignature.initVerify(publicKey);
        ecdsaSignature.update(data);
        return ecdsaSignature.verify(signature);
    }
}
