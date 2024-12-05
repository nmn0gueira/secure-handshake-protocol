package pt.unl.fct.shp.crypto;

import pt.unl.fct.common.crypto.CustomKeyAgreement;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.*;

public class ShpKeyAgreement implements CustomKeyAgreement {

    private static final KeyPairGenerator DIFFIE_HELLMAN_KEY_PAIR_GENERATOR;
    private static final KeyAgreement DIFFIE_HELLMAN_KEY_AGREEMENT;

    /*
     * Pre-computed values for the primitive root G and
     * prime number P, that will be used for the dynamic key-agreement
     *
     */
    private static final BigInteger G_512 = new BigInteger(
            "153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7"
                    + "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b"
                    + "410b7a0f12ca1cb9a428cc", 16);

    private static final BigInteger P_512 = new BigInteger(
            "9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387"
                    + "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b"
                    + "f0573bf047a3aca98cdf3b", 16);

    private static final DHParameterSpec DH_PARAMETER_SPEC = new DHParameterSpec(P_512, G_512);

    static {
        try {
            DIFFIE_HELLMAN_KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance("DH", "BC");
            DIFFIE_HELLMAN_KEY_PAIR_GENERATOR.initialize(DH_PARAMETER_SPEC);
            DIFFIE_HELLMAN_KEY_AGREEMENT = KeyAgreement.getInstance("DH", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    private final KeyPair keyPair;

    public ShpKeyAgreement()  {
        keyPair = DIFFIE_HELLMAN_KEY_PAIR_GENERATOR.generateKeyPair();
        try {
            DIFFIE_HELLMAN_KEY_AGREEMENT.init(keyPair.getPrivate());
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void doPhase(PublicKey publicKey) throws InvalidKeyException {
        DIFFIE_HELLMAN_KEY_AGREEMENT.doPhase(publicKey, true);
    }

    @Override
    public byte[] generateSecret() {
        return DIFFIE_HELLMAN_KEY_AGREEMENT.generateSecret();
    }

    @Override
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }
}
