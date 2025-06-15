
import java.net.Socket;
import java.util.Map;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient2.class.getSimpleName();

    public static void main(String[] args) {
        try {
            Arguments arguments = ArgumentParser.parse(args, Map.of(
                    "host", "hostname",
                    "port", "portnumber",
                    "usercert", "filename",
                    "cacert", "filename",
                    "key", "filename"
            ));

            String host = arguments.get("host");
            int port = Integer.parseInt(arguments.get("port"));
            Socket socket = ConnectionManager.connectToServer(host, port);

            HandshakeInfo hs = SecureHandshakeManager.performClientHandshake(socket, arguments);

            Forwarder.forwardStreams(System.in, hs.secureOut, hs.secureIn, System.out, socket);
        } catch (Exception e) {
            System.err.println("[" + PROGRAMNAME + "] Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
