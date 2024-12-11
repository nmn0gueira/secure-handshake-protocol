package pt.unl.fct.shp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import pt.unl.fct.common.Utils;
import pt.unl.fct.common.crypto.KeyLoader;
import pt.unl.fct.shp.crypto.ShpCryptoSpec;
import pt.unl.fct.shp.crypto.ShpKeyAgreement;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class RandomTest {

    private static final KeyFactory DIFFIE_HELLMAN_KEY_FACTORY;

    private static final KeyPairGenerator ECDSA_KEY_PAIR_GENERATOR;
    private static final ECGenParameterSpec EC_GEN_PARAMETER_SPEC = new ECGenParameterSpec("secp256k1");

    static {
        Security.addProvider(new BouncyCastleProvider());

        try {
            ECDSA_KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance("ECDSA", "BC");
            ECDSA_KEY_PAIR_GENERATOR.initialize(EC_GEN_PARAMETER_SPEC, new SecureRandom());
            DIFFIE_HELLMAN_KEY_FACTORY = KeyFactory.getInstance("DH", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testECDSAKey() {
        // Generate a key pair
        KeyPair keyPair = ECDSA_KEY_PAIR_GENERATOR.generateKeyPair();
        System.out.println("Public key: " + Utils.byteArrayToHexString(keyPair.getPublic().getEncoded()));
        System.out.println("Private key: " + Utils.byteArrayToHexString(keyPair.getPrivate().getEncoded()));
    }

    @Test
    public void testPasswordHash() {
        // Test the password hashing
        String password = "password";
        byte[] passwordHash = ShpCryptoSpec.digest(password.getBytes());
        System.out.println("Password: " + Utils.byteArrayToHexString(passwordHash));
    }

    @Test
    public void testPBE() {
        // Test the PBE
        String password = "password";
        byte[] passwordDigest = ShpCryptoSpec.digest(password.getBytes());
        System.out.println("Password hash :" + Utils.byteArrayToHexString(passwordDigest));
        System.out.println("--");
        String digestString = new String(passwordDigest);
        System.out.println(digestString);
        for (char c : digestString.toCharArray()) {
            System.out.print((int)c + " ");
        }
    }

    @Test
    public void testDivideInParts() {
        byte[] data = new byte[100];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        byte[][] parts = Utils.divideInParts(data, 10, 15);
        System.out.println(parts.length);
        for (byte[] part : parts) {
            System.out.println("Length: " + part.length);
            System.out.println("Array: " + Utils.byteArrayToHexString(part));
        }
    }
    @Test
    public void testDiffieHellman() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "BC");

        byte[] publicKeyA = Utils.hexStringToByteArray("3081dc30819306092a864886f70d0103013081850241009494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b0240153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc03440002410081e313591bfc7e929666f533c32c6ac10ce9923377e8e15303129a3f1891e462fc78bc62025cb413aa27b60e9b456d6f694f1014fc6de9c3069266a80000802b");
        byte[] privateKeyA = Utils.hexStringToByteArray("3081dd02010030819306092a864886f70d0103013081850241009494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b0240153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc04420240391a32517488c3b3cc7939fb68b43a5e6635b8420646d8a2575ed28b53abbefd4c453eae0597583f2e152b24d2d4224342ae5c2cdaa79b1bd951c3750b1b698f");
        byte[] publicKeyB = Utils.hexStringToByteArray("3081db30819306092a864886f70d0103013081850241009494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b0240153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc034300024015eea93b279bd725e92031c61a33a4ec4a810bc7904d866e17fb81cb5729aa24b2c7b930ea9af1a4062c403f512d7e999d50339be3ce360177599d07952c54aa");
        byte[] privateKeyB = Utils.hexStringToByteArray("3081dd02010030819306092a864886f70d0103013081850241009494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b0240153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc044202403c364228b2423791e8fa2118e9eaabb74a93ec75c86e1a1a55e1e8d2aba125765dc766da76d79575724bf7233c822efd04faca8b60b237833d38434385265afd");
        PublicKey publicKeyAKey = KeyLoader.loadPublicKey(publicKeyA, DIFFIE_HELLMAN_KEY_FACTORY);
        PrivateKey privateKeyAKey = KeyLoader.loadPrivateKey(privateKeyA, DIFFIE_HELLMAN_KEY_FACTORY);
        PublicKey publicKeyBKey = KeyLoader.loadPublicKey(publicKeyB, DIFFIE_HELLMAN_KEY_FACTORY);
        PrivateKey privateKeyBKey = KeyLoader.loadPrivateKey(privateKeyB, DIFFIE_HELLMAN_KEY_FACTORY);
        System.out.println("Public key A: " + Utils.byteArrayToHexString(publicKeyAKey.getEncoded()));
        System.out.println("Private key A: " + Utils.byteArrayToHexString(privateKeyAKey.getEncoded()));
        System.out.println("Public key B: " + Utils.byteArrayToHexString(publicKeyBKey.getEncoded()));
        System.out.println("Private key B: " + Utils.byteArrayToHexString(privateKeyBKey.getEncoded()));

        aKeyAgree.init(privateKeyAKey);
        bKeyAgree.init(privateKeyBKey);

        aKeyAgree.doPhase(publicKeyBKey, true);

        bKeyAgree.doPhase(publicKeyAKey, true);

        byte[] aShared = aKeyAgree.generateSecret();

        byte[] bShared = bKeyAgree.generateSecret();

        System.out.println("Alice: I generated\n" + Utils.byteArrayToHexString(aShared));

        System.out.println("Bob: I generated\n" + Utils.byteArrayToHexString(bShared));
    }

    @Test
    public void shpDiffieHellmanTest() {
        ShpKeyAgreement alice = new ShpKeyAgreement();
        ShpKeyAgreement bob = new ShpKeyAgreement();
        byte[] publicKeyABytes = alice.getPublicKey().getEncoded();
        byte[] publicKeyBBytes = bob.getPublicKey().getEncoded();

        try {
            alice.doPhase(KeyLoader.loadPublicKey(publicKeyBBytes, DIFFIE_HELLMAN_KEY_FACTORY));
            bob.doPhase(KeyLoader.loadPublicKey(publicKeyABytes, DIFFIE_HELLMAN_KEY_FACTORY));
            byte[] aliceShared = alice.generateSecret();
            byte[] bobShared = bob.generateSecret();
            System.out.println("Alice: I generated\n" + Utils.byteArrayToHexString(aliceShared));
            System.out.println("Bob: I generated\n" + Utils.byteArrayToHexString(bobShared));
        } catch (InvalidKeyException e) {
            System.out.println("Invalid key");
        }
    }
    /*
    @Test
    public void shpDiffieHellmanTest2() {
        ShpCryptoSpec alice = new ShpCryptoSpec();
        ShpCryptoSpec bob = new ShpCryptoSpec();

        try {
            byte[] aliceShared = alice.generateSharedKey(bob.getYdhBytes());
            byte[] bobShared = bob.generateSharedKey(alice.getYdhBytes());
            System.out.println("Alice: I generated\n" + Utils.byteArrayToHexString(aliceShared));
            System.out.println("Bob: I generated\n" + Utils.byteArrayToHexString(bobShared));
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void shpDiffieHellmanTest3() {
        ShpCryptoSpec alice = new ShpCryptoSpec();
        ShpCryptoSpec bob = new ShpCryptoSpec();

        try {
            alice.doPhase(bob.getYdhBytes());
            byte[] aliceShared = alice.generateSecret();
            bob.doPhase(alice.getYdhBytes());
            byte[] bobShared = bob.generateSecret();
            System.out.println("Alice: I generated\n" + Utils.byteArrayToHexString(aliceShared));
            System.out.println("Bob: I generated\n" + Utils.byteArrayToHexString(bobShared));
        } catch (InvalidKeyException e) {
            e.printStackTrace();
       */
}
