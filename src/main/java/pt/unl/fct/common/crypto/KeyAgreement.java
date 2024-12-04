package pt.unl.fct.common.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public interface KeyAgreement {

    KeyAgreement createKeyAgreement() throws NoSuchAlgorithmException, NoSuchProviderException;
}
