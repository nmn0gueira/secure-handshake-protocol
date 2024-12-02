package pt.unl.fct.shp.server;

import java.security.PublicKey;

public record User(String userId, byte[] passwordHash, byte[] salt, PublicKey publicKey) {
    public User {
        if (userId == null || passwordHash == null || salt == null || publicKey == null) {
            throw new IllegalArgumentException("User fields cannot be null");
        }
    }
}
