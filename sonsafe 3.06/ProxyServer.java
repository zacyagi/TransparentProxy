import java.io.IOException;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

public class ProxyServer extends Thread {
    private ServerSocket httpSocket;
    private ServerSocket httpsSocket;
    private boolean running;

    public void run() {
        try {
            httpSocket = new ServerSocket(80);
            httpsSocket = new ServerSocket(443);
            running = true;
            System.out.println("Proxy server started on ports 80 and 443");

            // Start a thread for HTTP connections
            new Thread(() -> handleConnections(httpSocket, "HTTP")).start();
            // Start a thread for HTTPS connections
            new Thread(() -> handleConnections(httpsSocket, "HTTPS")).start();

        } catch (BindException e) {
            System.err.println("Port is already in use.");
        } catch (IOException e) {
            System.err.println("I/O exception occurred.");
        } catch (Exception e) {
            System.err.println("Unexpected exception occurred.");
        }
    }

    private void handleConnections(ServerSocket serverSocket, String protocol) {
        while (running) {
            try {
                Socket clientSocket = serverSocket.accept();
                System.out.println("New " + protocol + " client connected: " + clientSocket.getInetAddress());
                new ProxyHandler(clientSocket,protocol).start();
            } catch (SocketException e) {
                // Ignore it
            } catch (IOException e) {
                System.err.println("I/O exception occurred in " + protocol + " handler.");
            }
        }
    }

    public synchronized void stopServer() {
        running = false;
        try {
            if (httpSocket != null) {
                httpSocket.close();
            }
            if (httpsSocket != null) {
                httpsSocket.close();
            }
        } catch (IOException e) {
            // Ignore it
        }
    }

    public boolean isRunning() {
        return running;
    }
}
