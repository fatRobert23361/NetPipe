
import java.net.Socket;
import java.util.Map;

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();

    public static void main(String[] args) {
        try {
            Arguments arguments = ArgumentParser.parse(args, Map.of(
                    "port", "portnumber",
                    "usercert", "filename",
                    "cacert", "filename",
                    "key", "filename"
            ));

            int port = Integer.parseInt(arguments.get("port"));
            Socket socket = ConnectionManager.waitForClient(port);

            HandshakeInfo hs = SecureHandshakeManager.performServerHandshake(socket, arguments);

            Forwarder.forwardStreams(System.in, hs.secureOut, hs.secureIn, System.out, socket);
        } catch (Exception e) {
            System.err.println("[" + PROGRAMNAME + "] Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
