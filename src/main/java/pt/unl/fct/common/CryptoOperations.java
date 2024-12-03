package pt.unl.fct.common;

import java.security.*;
import java.security.spec.InvalidKeySpecException;

public interface CryptoOperations {
    KeyPair generateKeyPair();
    byte[] sign(PrivateKey privateKey, byte[] message) throws InvalidKeyException, SignatureException;
    boolean verify(PublicKey publicKey, byte[] message, byte[] signature) throws InvalidKeyException, SignatureException;
    PublicKey loadPublicKey(byte[] publicKeyBytes) throws InvalidKeySpecException;
    PrivateKey loadPrivateKey(byte[] privateKeyBytes) throws InvalidKeySpecException;
}