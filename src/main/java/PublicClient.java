import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.naming.ServiceUnavailableException;

import com.github.scribejava.apis.MicrosoftAzureActiveDirectoryApi;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthAsyncRequestCallback;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.github.scribejava.core.oauth.OAuth20Service;



public class PublicClient {

    private final static String AUTHORITY = "https://login.microsoftonline.com/common/";
    private final static String CLIENT_ID = "09e357af-11a5-45c0-b94a-731418c5998a";

    public static void main(String args[]) throws Exception {

        try (BufferedReader br = new BufferedReader(new InputStreamReader(
                System.in))) {
            System.out.print("Enter username: ");
            String username = br.readLine();
            System.out.print("Enter password: ");
            String password = br.readLine();

            if (!username.isEmpty()) {
                AuthenticationResult result = getAccessTokenFromUserCredentials_10(
                        username, password);
                System.out.println("Access Token - " + result.getAccessToken());
                System.out.println("Refresh Token - " + result.getRefreshToken());
                System.out.println("ID Token - " + result.getIdToken());

            } else {

                String[] authResult = getAccessTokenFromUserCredentials_20();
                System.out.println("Access Token - " + authResult[0]);
                System.out.println("Refresh Token - " + authResult[1]);
                System.out.println("Expires in - " + authResult[2]);

            }
        }
    }

    private static String[] getAccessTokenFromUserCredentials_20() throws Exception {


        try (OAuth20Service service = new ServiceBuilder(CLIENT_ID)
                .callback("http://localhost")
                .scope("openid")
                .apiSecret("mkjocRKSQ40|;lmERW843#~")
                .build(MicrosoftAzureActiveDirectoryApi.instance())) {
            String authorizationUrl = service.getAuthorizationUrl();
            System.out.println(authorizationUrl);
            String authorizationCode = "";
            OAuth2AccessToken accessToken = service.getAccessToken(authorizationCode);
            String [] results = {
                    accessToken.getAccessToken()
                    ,accessToken.getRefreshToken()
                    ,accessToken.getExpiresIn().toString()};
            return results;
        }

    }
    private static AuthenticationResult getAccessTokenFromUserCredentials_10(
            String username, String password) throws Exception {
        AuthenticationContext context = null;
        AuthenticationResult result = null;
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);
            context = new AuthenticationContext(AUTHORITY, false, service);
            Future<AuthenticationResult> future = context.acquireToken(
                    "https://graph.windows.net", CLIENT_ID, username, password,
                    null);
            result = future.get();

        } catch (ExecutionException ex) {
            if (ex.getCause() != null) {
                String exceptionMessage = ex.getCause().getMessage();
                if (exceptionMessage != null) {
                    System.out.println(exceptionMessage);
                }
            } else {
                System.out.println(ex.getMessage());
            }

        } finally {
            service.shutdown();
        }

        if (result == null) {
            throw new ServiceUnavailableException(
                    "authentication result was null");
        }
        return result;
    }
}
