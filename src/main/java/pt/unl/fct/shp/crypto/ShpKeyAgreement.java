package pt.unl.fct.shp.crypto;

import pt.unl.fct.common.crypto.KeyAgreement;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class ShpKeyAgreement implements KeyAgreement {

        private final KeyPairGenerator keyPairGenerator;
        private final KeyAgreement keyAgreement;

        public ShpKeyAgreement() {
            try {
                keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
                keyAgreement = KeyAgreement.getInstance("DH", "BC");
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public KeyPair generateKeyPair() {
            return keyPairGenerator.generateKeyPair();
        }

        @Override
        public void init(PrivateKey privateKey) {
            try {
                keyAgreement.init(privateKey);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void doPhase(PublicKey publicKey) {
            try {
                keyAgreement.doPhase(publicKey, true);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public byte[] generateSecret() {
            return keyAgreement.generateSecret();
        }

    @Override
    public KeyAgreement createKeyAgreement() throws NoSuchAlgorithmException, NoSuchProviderException {
        return KeyAgreement.getInstance("DH", "BC");
    }
}
