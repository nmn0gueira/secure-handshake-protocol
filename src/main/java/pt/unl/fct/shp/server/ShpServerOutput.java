package pt.unl.fct.shp.server;

public record ShpServerOutput(String request, int udpPort, String cryptoConfig, byte[] sharedSecret) {
}
