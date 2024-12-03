package pt.unl.fct.common;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class CryptoConfig {
    private Properties properties;

    public CryptoConfig(String configFile) throws IOException {
        properties = new Properties();
        try (InputStream input = getClass().getClassLoader().getResourceAsStream(configFile)) {
            if (input == null) {
                throw new IOException("Configuration file not found: " + configFile);
            }
            properties.load(input);
        }
    }

    public String getProperty(String key) {
        return properties.getProperty(key);
    }
}