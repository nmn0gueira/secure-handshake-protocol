package pt.unl.fct.common.crypto;

import java.security.*;

public interface DigitalSignature {
    byte[] sign(PrivateKey privateKey, byte[] message) throws InvalidKeyException, SignatureException;
    boolean verify(PublicKey publicKey, byte[] message, byte[] signature) throws InvalidKeyException, SignatureException;
    int getSignatureLength();
}
