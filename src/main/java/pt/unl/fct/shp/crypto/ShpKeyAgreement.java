package pt.unl.fct.shp.crypto;

import pt.unl.fct.common.crypto.CustomKeyAgreement;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.*;

public class ShpKeyAgreement implements CustomKeyAgreement {
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


    private final KeyPair keyPair;
    private final KeyAgreement diffieHellmanKeyAgreement;

    public ShpKeyAgreement()  {
        try {
            KeyPairGenerator dhkpg = KeyPairGenerator.getInstance("DH", "BC");
            dhkpg.initialize(DH_PARAMETER_SPEC);
            keyPair = dhkpg.generateKeyPair();
            diffieHellmanKeyAgreement = KeyAgreement.getInstance("DH", "BC");
            diffieHellmanKeyAgreement.init(keyPair.getPrivate());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void doPhase(PublicKey publicKey) throws InvalidKeyException {
        diffieHellmanKeyAgreement.doPhase(publicKey, true);
    }

    @Override
    public byte[] generateSecret() {
        return diffieHellmanKeyAgreement.generateSecret();
    }

    @Override
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }
}
