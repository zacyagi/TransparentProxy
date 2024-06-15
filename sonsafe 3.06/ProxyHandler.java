import java.io.*;
import java.net.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class ProxyHandler extends Thread {
    private Socket clientSocket;
    private DataInputStream dIS;
    private DataOutputStream dOS;
    private BufferedReader clientInput;
    private static Map<String, byte[]> cache = new HashMap<>();
    private static Map<String, Long> cacheLastModified = new HashMap<>();
    private String protocol;
    public static List<String> filteredDomains = new ArrayList<>();
    private static boolean isFilteringEnabled=false;
    private static final String LOGIN_PAGE = "<html><body><h2>Login Page</h2><form method='post'>Token: <input type='text' name='token'><input type='submit' value='Submit'></form></body></html>";
    private static final Map<String, Boolean> clientTokens = new ConcurrentHashMap<>();

    public ProxyHandler(Socket clientSocket, String protocol) {
        this.clientSocket = clientSocket;
        this.protocol = protocol;
        try {
            clientInput = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            dIS = new DataInputStream(clientSocket.getInputStream());
            dOS = new DataOutputStream(clientSocket.getOutputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        try {
        	String clientIP = clientSocket.getInetAddress().getHostAddress();
        	if (!clientTokens.containsKey(clientIP)) {
                String requestLine = clientInput.readLine();
                String[] tokens = requestLine.split(" ");
                String method = tokens[0];
                if ("POST".equalsIgnoreCase(method)) {
                    handleTokenSubmission();
                    return;
                } else {
                    serveLoginPage();
                    return;
                }
            }
        	int a=0;
            String header = readHeader(dIS);
            int fsp = header.indexOf(' ');
            if (fsp == -1) {
                System.out.println("BAD FSP VALUE");
                return;
            }
            int ssp = header.indexOf(' ', fsp + 1);
            int secondline = header.indexOf('\r') + 2;
            System.out.println("FSP IS: " + fsp);
            String host = extractHost(header);
            System.out.println("host is: " + host);
            String method = header.substring(0, fsp);
            System.out.println("method is: " + method);
            String fullpath = header.substring(fsp + 1, ssp);
            System.out.println("fullpath is: " + fullpath);
            if (fullpath.startsWith("/") && protocol.equals("HTTP")) {
                System.out.println("HTTP SLAŞLA BAŞLIYOOOOOOOOOOOOOOOOOOO");
                fullpath = "http://" + host + fullpath;
            }
            if(a==1){
                InputStream serverInputStream = clientSocket.getInputStream();
                OutputStream serverOutputStream = clientSocket.getOutputStream();
                readSNI(serverInputStream );
                relayRequest(serverInputStream,serverOutputStream);
                relayResponse(serverInputStream,serverOutputStream);
            }
            String restHeader = header.substring(secondline);
            if (method.equals("CONNECT")) {
                String[] hostPort = fullpath.split(":");
                String hostName = hostPort[0];
                boolean isFiltered = filteredDomains.stream().anyMatch(hostName::contains);
                if (isFiltered && isFilteringEnabled) {
                    System.out.println("Https Request But filtered");
                    sendError(HttpMethod.UNAUTHORIZED);
                    sendUnauthorized();
                    return;
                }
                handleHttpsRequest(fullpath);
                return;
            }

            URL url = null;
            try {
                url = new URL(fullpath);
            } catch (MalformedURLException e) {
                //e.printStackTrace();
            }
            if (url != null) {
                String domain = url.getHost();
                boolean isFiltered = filteredDomains.stream().anyMatch(domain::contains);
                if (isFiltered && isFilteringEnabled) {
                    sendError(HttpMethod.UNAUTHORIZED);
                    sendUnauthorized();
                } else {
                    if (HttpMethod.isSupported(method)) {
                        if (method.equals("HEAD")) {
                            byte[] responseHead = handleHeadRequest(url, restHeader);
                            sendResponse(responseHead);
                            System.out.println("AUTHORIZED");
                        } else if (method.equals("GET")) {
                            byte[] responseGet;
                            boolean flag = false;
                            if (isCached(url)) {
                                flag = true;
                                responseGet = getCached(url);
                                System.out.println("CACHEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE");
                            } else {
                                responseGet = handleGetRequest(url, restHeader);
                                cacheResponse(url, responseGet);
                            }
                            if (flag == true && responseGet == null) {
                                System.out.println("CACHE UNAUTHORIZED");
                                responseGet = handleGetRequest(url, restHeader);
                                cacheResponse(url, responseGet);
                            }
                            sendResponse(responseGet);
                            System.out.println("AUTHORIZED");
                        } else if (method.equals("OPTIONS")) {
                            byte[] responseOptions = handleOptionsRequest(url, restHeader);
                            sendResponse(responseOptions);
                            System.out.println("AUTHORIZED");
                        } else if (method.equals("POST")) {
                            byte[] responsePost = handlePostRequest(url, restHeader);
                            sendResponse(responsePost);
                            System.out.println("AUTHORIZED");
                        }
                    } else {
                        sendError(HttpMethod.NOT_ALLOWED);
                        sendNotAllowed();
                    }
                }
            }
        } catch (IOException e) {
            //e.printStackTrace();
        } finally {
            try {
                if (clientSocket != null) clientSocket.close();
            } catch (IOException e) {
                //e.printStackTrace();
            }
        }
    }

    
    
    private boolean isCached(URL url) {
        String urlString = url.toString();
        return cache.containsKey(urlString) && cacheLastModified.containsKey(urlString);
    }

    private byte[] getCached(URL url) {
        String urlString = url.toString();
        long lastModified = cacheLastModified.get(urlString);
        long currentTime = System.currentTimeMillis();
        // Cache is considered expired after 1 hour
        if ((currentTime - lastModified > 3600000) || isResourceUpdated(url)) {
            cache.remove(urlString);
            cacheLastModified.remove(urlString);
            System.out.println("CACHE EXPIRED OR SITE UPDATED.");
            return null;
        }
        return cache.get(urlString);
    }

    private boolean isResourceUpdated(URL url) {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("HEAD");
            long lastModifiedRemote = connection.getLastModified();
            if (lastModifiedRemote == 0) {
                // Doesn't support lastModified
                return true;
            }

            String urlString = url.toString();
            long lastModifiedLocal = cacheLastModified.getOrDefault(urlString, 0L);
            System.out.println("LAST MODIFIED IS: " + lastModifiedLocal);
            System.out.println("LAST REMOTE IS: " + lastModifiedRemote);
            return lastModifiedRemote > lastModifiedLocal;
        } catch (IOException e) {
            e.printStackTrace();
            return false; // Hata durumunda kaynak güncellenmiş olarak kabul edilmez
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private void cacheResponse(URL url, byte[] response) {
        String urlString = url.toString();
        cache.put(urlString, response);
        cacheLastModified.put(urlString, System.currentTimeMillis());
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter("cache.txt", true));
            writer.write(urlString + "\n");
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    private String readSNI(InputStream inputStream) throws IOException {
        byte[] buffer = new byte[8192];
        int bytesRead = inputStream.read(buffer);
        String request = new String(buffer, 0, bytesRead);
        // Extract SNI from the client's request
        // SNI starts after the Client Hello message
        int startIndex = request.indexOf("ClientHello") + "ClientHello".length();
        int endIndex = request.indexOf("\r\n", startIndex);
        return request.substring(startIndex, endIndex);
    }

    private void relayRequest(InputStream clientInput, OutputStream serverOutput) throws IOException {
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = clientInput.read(buffer)) != -1) {
            serverOutput.write(buffer, 0, bytesRead);
        }
        serverOutput.flush();
    }

    private void relayResponse(InputStream serverInput, OutputStream clientOutput) throws IOException {
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = serverInput.read(buffer)) != -1) {
            clientOutput.write(buffer, 0, bytesRead);
        }
        clientOutput.flush();
    }
    
    private byte[] handleOptionsRequest(URL url, String headers) throws IOException {
        final int BUFFER_SIZE = 4096;
        byte[] responseBytes = null;
        try (Socket socket = new Socket(url.getHost(), url.getPort() == -1 ? 80 : url.getPort());
             InputStream serverInputStream = socket.getInputStream();
             OutputStream serverOutputStream = socket.getOutputStream();
             ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
             PrintWriter writer = new PrintWriter(serverOutputStream, true)) {

            // Manage headers to avoid duplicates
            Set<String> headerSet = new HashSet<>();
            StringBuilder requestBuilder = new StringBuilder();
            requestBuilder.append("OPTIONS ").append(url.getFile()).append(" HTTP/1.1\r\n");

            // Split headers and add them if not already added
            String[] lines = headers.split("\r\n");
            for (String line : lines) {
                int colonIndex = line.indexOf(':');
                if (colonIndex != -1) {
                    String headerName = line.substring(0, colonIndex).trim();
                    if (!headerSet.contains(headerName)) {
                        requestBuilder.append(line).append("\r\n");
                        headerSet.add(headerName);
                    }
                }
            }

            // Add Host if not already included
            if (!headerSet.contains("Host")) {
                requestBuilder.append("Host: ").append(url.getHost()).append("\r\n");
            }

            requestBuilder.append("Connection: close\r\n\r\n");

            // Log the complete request for debugging
            System.out.println("Complete OPTIONS Request:\n" + requestBuilder.toString());
            LocalDateTime currentDateTime = LocalDateTime.now();
            try (BufferedWriter writer1 = new BufferedWriter(new FileWriter("log.txt", true))) {
                writer1.write("Ip Addr: " + clientSocket.getInetAddress());
                writer1.newLine();
                writer1.write("Date: " + currentDateTime);
                writer1.newLine();
                writer1.write("Url is: " + url);
                writer1.newLine();
                writer1.write("Method is: OPTIONS");
                writer1.newLine();
                writer1.write("Status Code: 200");
                writer1.newLine();
                writer1.write("@@@");
                writer1.newLine();
            } catch (IOException e) {
                e.printStackTrace();
            }
            // Send the request
            writer.print(requestBuilder.toString());
            writer.flush();

            // Read the response headers
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = serverInputStream.read(buffer)) != -1) {
                responseStream.write(buffer, 0, bytesRead); // Write response to ByteArrayOutputStream
            }

            responseBytes = responseStream.toByteArray(); // Convert ByteArrayOutputStream to byte array
        }

        return responseBytes;
    }

    private byte[] handleHeadRequest(URL url, String headers) throws IOException {
        final int BUFFER_SIZE = 4096;
        byte[] responseBytes = null;
        try (Socket socket = new Socket(url.getHost(), url.getPort() == -1 ? 80 : url.getPort());
             InputStream serverInputStream = socket.getInputStream();
             OutputStream serverOutputStream = socket.getOutputStream();
             ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
             PrintWriter writer = new PrintWriter(serverOutputStream, true)) {

            // Manage headers to avoid duplicates
            Set<String> headerSet = new HashSet<>();
            StringBuilder requestBuilder = new StringBuilder();
            requestBuilder.append("HEAD ").append(url.getFile()).append(" HTTP/1.1\r\n");

            // Split headers and add them if not already added
            String[] lines = headers.split("\r\n");
            for (String line : lines) {
                int colonIndex = line.indexOf(':');
                if (colonIndex != -1) {
                    String headerName = line.substring(0, colonIndex).trim();
                    if (!headerSet.contains(headerName)) {
                        requestBuilder.append(line).append("\r\n");
                        headerSet.add(headerName);
                    }
                }
            }

            // Add Host if not already included
            if (!headerSet.contains("Host")) {
                requestBuilder.append("Host: ").append(url.getHost()).append("\r\n");
            }

            requestBuilder.append("Connection: close\r\n\r\n");

            // Log the complete request for debugging
            System.out.println("Complete HEAD Request:\n" + requestBuilder.toString());
            LocalDateTime currentDateTime = LocalDateTime.now();
            try (BufferedWriter writer1 = new BufferedWriter(new FileWriter("log.txt", true))) {
                writer1.write("Ip Addr: " + clientSocket.getInetAddress());
                writer1.newLine();
                writer1.write("Date: " + currentDateTime);
                writer1.newLine();
                writer1.write("Url is: " + url);
                writer1.newLine();
                writer1.write("Method is: HEAD");
                writer1.newLine();
                writer1.write("Status Code: 200");
                writer1.newLine();
                writer1.write("@@@");
                writer1.newLine();
            } catch (IOException e) {
                e.printStackTrace();
            }
            // Send the request
            writer.print(requestBuilder.toString());
            writer.flush();

            // Read the response headers
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = serverInputStream.read(buffer)) != -1) {
                responseStream.write(buffer, 0, bytesRead); // Write response to ByteArrayOutputStream
            }

            responseBytes = responseStream.toByteArray(); // Convert ByteArrayOutputStream to byte array
        }

        return responseBytes;
    }

    private byte[] handleGetRequest(URL url, String headers) throws IOException {
        final int BUFFER_SIZE = 4096;
        try (Socket socket = new Socket(url.getHost(), url.getPort() == -1 ? 80 : url.getPort());
             InputStream serverInputStream = socket.getInputStream();
             OutputStream serverOutputStream = socket.getOutputStream();
             ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
             PrintWriter writer = new PrintWriter(serverOutputStream, true)) {

            // Manage headers to avoid duplicates
            Set<String> headerSet = new HashSet<>();
            StringBuilder requestBuilder = new StringBuilder();
            requestBuilder.append("GET ").append(" ").append(url.getFile()).append(" HTTP/1.1\r\n");

            // Split headers and add them if not already added
            String[] lines = headers.split("\r\n");
            for (String line : lines) {
                int colonIndex = line.indexOf(':');
                if (colonIndex != -1) {
                    String headerName = line.substring(0, colonIndex).trim();
                    if (!headerSet.contains(headerName)) {
                        requestBuilder.append(line).append("\r\n");
                        headerSet.add(headerName);
                    }
                }
            }

            // Add Host if not already included
            if (!headerSet.contains("Host")) {
                requestBuilder.append("Host: ").append(url.getHost()).append("\r\n");
            }

            requestBuilder.append("Connection: close\r\n\r\n");

            // Log the complete request for debugging
            System.out.println("Complete Request:\n" + requestBuilder.toString());
            LocalDateTime currentDateTime = LocalDateTime.now();
            try (BufferedWriter writer1 = new BufferedWriter(new FileWriter("log.txt", true))) {
                writer1.write("Ip Addr: " + clientSocket.getInetAddress());
                writer1.newLine();
                writer1.write("Date: " + currentDateTime);
                writer1.newLine();
                writer1.write("Url is: " + url);
                writer1.newLine();
                writer1.write("Method is: GET");
                writer1.newLine();
                writer1.write("Status Code: 200");
                writer1.newLine();
                writer1.write("@@@");
                writer1.newLine();
            } catch (IOException e) {
                e.printStackTrace();
            }

            // Send the request
            writer.print(requestBuilder.toString());
            writer.flush();

            // Read and print the response for debugging
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = serverInputStream.read(buffer)) != -1) {
                responseStream.write(buffer, 0, bytesRead);
                //System.out.write(buffer, 0, bytesRead);  // Print the raw response for debugging
            }

            return responseStream.toByteArray();
        }
    }

    private byte[] handlePostRequest(URL url, String headers) throws IOException {
        final int BUFFER_SIZE = 4096;
        try (Socket socket = new Socket(url.getHost(), url.getPort() == -1 ? 80 : url.getPort());
             InputStream serverInputStream = socket.getInputStream();
             OutputStream serverOutputStream = socket.getOutputStream();
             ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
             PrintWriter writer = new PrintWriter(serverOutputStream, true)) {

            // Manage headers to avoid duplicates
            Set<String> headerSet = new HashSet<>();
            StringBuilder requestBuilder = new StringBuilder();
            requestBuilder.append("POST ").append(" ").append(url.getFile()).append(" HTTP/1.1\r\n");

            // Split headers and add them if not already added
            String[] lines = headers.split("\r\n");
            for (String line : lines) {
                int colonIndex = line.indexOf(':');
                if (colonIndex != -1) {
                    String headerName = line.substring(0, colonIndex).trim();
                    if (!headerSet.contains(headerName)) {
                        requestBuilder.append(line).append("\r\n");
                        headerSet.add(headerName);
                    }
                }
            }

            // Add Host if not already included
            if (!headerSet.contains("Host")) {
                requestBuilder.append("Host: ").append(url.getHost()).append("\r\n");
            }

            requestBuilder.append("Connection: close\r\n\r\n");

            // Log the complete request for debugging
            System.out.println("Complete POST Request:\n" + requestBuilder.toString());
            LocalDateTime currentDateTime = LocalDateTime.now();
            try (BufferedWriter writer1 = new BufferedWriter(new FileWriter("log.txt", true))) {
                writer1.write("Ip Addr: " + clientSocket.getInetAddress());
                writer1.newLine();
                writer1.write("Date: " + currentDateTime);
                writer1.newLine();
                writer1.write("Url is: " + url);
                writer1.newLine();
                writer1.write("Method is: POST");
                writer1.newLine();
                writer1.write("Status Code: 200");
                writer1.newLine();
                writer1.write("@@@");
                writer1.newLine();
            } catch (IOException e) {
                e.printStackTrace();
            }
            // Send the request
            writer.print(requestBuilder.toString());
            writer.flush();

            // Read and print the response for debugging
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = serverInputStream.read(buffer)) != -1) {
                responseStream.write(buffer, 0, bytesRead);
                //System.out.write(buffer, 0, bytesRead);  // Print the raw response for debugging
            }

            return responseStream.toByteArray();
        }
    }

    private String readHeader(DataInputStream dIS) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try {
            while (true) {
                int data = dIS.read();
                if (data == -1) {
                    break;
                }
                buffer.write(data);
                if (buffer.size() >= 4 && buffer.toByteArray()[buffer.size() - 4] == '\r' &&
                        buffer.toByteArray()[buffer.size() - 3] == '\n' && buffer.toByteArray()[buffer.size() - 2] == '\r' &&
                        buffer.toByteArray()[buffer.size() - 1] == '\n') {
                    break;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new String(buffer.toByteArray());
    }

    private void sendError(String errorCode) throws IOException {
        OutputStream clientOutputStream = clientSocket.getOutputStream();
        String response = "HTTP/1.1 " + errorCode + "\r\n\r\n";
        clientOutputStream.write(response.getBytes());
        clientOutputStream.flush();
    }

    private void sendResponse(byte[] response) throws IOException {
        dOS.write(response);
        dOS.flush();
    }

    private void handleHttpsRequest(String fullpath) {
        try {
            // Split the fullpath into host and port
            String[] hostPort = fullpath.split(":");          
            String host = hostPort[0];
            int port = hostPort.length > 1 ? Integer.parseInt(hostPort[1]) : 443;

            // Connect to the remote host
            Socket remoteSocket = new Socket(host, port);
            remoteSocket.setSoTimeout(10000);

            // Send HTTP/1.1 200 Connection Established to the client
            dOS.writeBytes("HTTP/1.1 200 Connection Established\r\n");
            dOS.writeBytes("Proxy-Agent: Java-Proxy\r\n");
            dOS.writeBytes("\r\n");
            dOS.flush();

            // Setup I/O streams
            DataInputStream remoteInputStream = new DataInputStream(remoteSocket.getInputStream());
            DataOutputStream remoteOutputStream = new DataOutputStream(remoteSocket.getOutputStream());

            // Create threads to forward data between client and remote server
            Thread clientToServer = new Thread(() -> forwardData(dIS, remoteOutputStream));
            Thread serverToClient = new Thread(() -> forwardData(remoteInputStream, dOS));

            // Start the threads
            clientToServer.start();
            serverToClient.start();

            // Wait for both threads to finish
            clientToServer.join();
            serverToClient.join();
            LocalDateTime currentDateTime = LocalDateTime.now();
            try (BufferedWriter writer1 = new BufferedWriter(new FileWriter("log.txt", true))) {
                writer1.write("Ip Addr: " + clientSocket.getInetAddress());
                writer1.newLine();
                writer1.write("Date: " + currentDateTime);
                writer1.newLine();
                writer1.write("Url is: " + host);
                writer1.newLine();
                writer1.write("Method is: CONNECT");
                writer1.newLine();
                writer1.write("Status Code: 200");
                writer1.newLine();
                writer1.write("@@@");
                writer1.newLine();
            } catch (IOException e) {
                e.printStackTrace();
            }
            // Close the remote connection
            remoteSocket.close();
        } catch (Exception e) {
            //e.printStackTrace();
        }
    }

    private void forwardData(DataInputStream inputStream, DataOutputStream outputStream) {
        try {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
                outputStream.flush();
            }
        } catch (IOException e) {
            //e.printStackTrace();
        }
    }

    private String extractHost(String headers) {
        String[] lines = headers.split("\r\n");
        for (String line : lines) {
            if (line.startsWith("Host:")) {
                return line.substring(5).trim();
            }
        }
        return null;
    }

    private void sendUnauthorized() {
        String response = "HTTP/1.1 401 Unauthorized\r\n";
        try {
            dOS.writeBytes(response);
        } catch (IOException e) {
            // Handle exception
        }
    }

    private void sendNotAllowed() {
        String response = "HTTP/1.1 405 Not Allowed\r\n";
        try {
            dOS.writeBytes(response);
        } catch (IOException e) {
            // Handle exception
        }
    }

    private void serveLoginPage() throws IOException {
        PrintWriter out = new PrintWriter(dOS, true);
        out.print("HTTP/1.1 200 OK\r\n");
        out.print("Content-Type: text/html\r\n");
        out.print("Content-Length: " + LOGIN_PAGE.length() + "\r\n");
        out.print("\r\n");
        out.print(LOGIN_PAGE);
        out.flush();
    }

    private void handleTokenSubmission() throws IOException {
        String clientIP = clientSocket.getInetAddress().getHostAddress();
        StringBuilder requestBody = new StringBuilder();

        while (!clientInput.readLine().isEmpty()) {
            // Read headers
        }
        while (clientInput.ready()) {
            requestBody.append((char) clientInput.read());
        }

        String token = extractTokenFromRequestBody(requestBody.toString());
        if (validateToken(token)) {
            isFilteringEnabled = "51e2cba401".equals(token);
            clientTokens.put(clientIP, isFilteringEnabled);
            System.out.println("Token Onaylandı!");
            serveSuccessPage();
        } else {
            System.out.println("Invalid Token");
            serveLoginPage();
        }
    }

    private String extractTokenFromRequestBody(String requestBody) {
        for (String param : requestBody.split("&")) {
            String[] pair = param.split("=");
            if (pair.length == 2 && "token".equals(pair[0])) {
                return pair[1];
            }
        }
        return null;
    }

    private boolean validateToken(String token) {
        return "8a21bce200".equals(token) || "51e2cba401".equals(token);
    }

    private void serveSuccessPage() throws IOException {
        String successPage = "<html><body><h2>Token accepted. You can now access the internet.</h2></body></html>";
        PrintWriter out = new PrintWriter(dOS, true);
        out.print("HTTP/1.1 200 OK\r\n");
        out.print("Content-Type: text/html\r\n");
        out.print("Content-Length: " + successPage.length() + "\r\n");
        out.print("\r\n");
        out.print(successPage);
        out.flush();
    }
    
    

}
