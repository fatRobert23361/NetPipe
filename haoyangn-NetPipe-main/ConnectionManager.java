import java.net.ServerSocket;
import java.net.Socket;

public class ConnectionManager {
    public static Socket connectToServer(String host, int port) throws Exception {
        return new Socket(host, port);
    }

    public static Socket waitForClient(int port) throws Exception {
        ServerSocket serverSocket = new ServerSocket(port);
        return serverSocket.accept();
    }
}