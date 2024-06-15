public class HttpMethod {
    public static final String GET = "GET";
    public static final String HEAD = "HEAD";
    public static final String OPTIONS = "OPTIONS";
    public static final String POST = "POST";
    public static final String CONNECT = "CONNECT";
    public static final String NOT_ALLOWED = "405 Method Not Allowed";
    public static final String UNAUTHORIZED = "401 Unauthorized";

    public static boolean isSupported(String method) {
        return method.equals(GET) || method.equals(HEAD) || method.equals(OPTIONS) || method.equals(POST) || method.equals(CONNECT);
    }
}
