package com.cgi.sharpe.a.david.barebonesoidc;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Controller
public class OIDCController {

    @GetMapping("/")
    public String index() {
        return "redirect:/login"; // Redirect to login page
    }

    @GetMapping("/login")
    public String login() {
        // Redirect to OIDC provider's authorization page
        // Construct the authorization request URL and redirect the user
        return "redirect:" + OIDCConfig.AUTHORIZATION_ENDPOINT + "?scope=openid&response_type=code&client_id=" + OIDCConfig.CLIENT_ID + "&redirect_uri=" + OIDCConfig.REDIRECT_URI;
    }

    @GetMapping("/callback")
    @ResponseBody
    public String callback(@RequestParam String code) throws Exception {
            // Construct the code verifier and code challenge, if PKCE is used
            // CodeVerifier codeVerifier = new CodeVerifier();

            // Prepare the token request
            AuthorizationCode authorizationCode = new AuthorizationCode(code);
            URI callbackUri = new URI(OIDCConfig.REDIRECT_URI);

            // Prepare client authentication
            ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID(OIDCConfig.CLIENT_ID), new Secret(OIDCConfig.CLIENT_SECRET));

            // Make the token request
            TokenRequest tokenRequest = new TokenRequest(
                    new URI(OIDCConfig.TOKEN_ENDPOINT),
                    clientAuth,
                    new AuthorizationCodeGrant(authorizationCode, callbackUri /*, codeVerifier */));

            HTTPResponse httpResponse = tokenRequest.toHTTPRequest().send();

            // Parse and handle the token response
            TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);

            if (tokenResponse instanceof TokenErrorResponse) {
                // Handle error
                TokenErrorResponse errorResponse = (TokenErrorResponse) tokenResponse;
                return "Error: " + errorResponse.getErrorObject().getDescription();
            }

            OIDCTokenResponse oidcTokenResponse = (OIDCTokenResponse) tokenResponse;
            AccessToken accessToken = oidcTokenResponse.getOIDCTokens().getAccessToken();

            // You can also retrieve the ID Token here
            JWT idToken = oidcTokenResponse.getOIDCTokens().getIDToken();

            // Optionally, retrieve user info
            // UserInfoRequest userInfoRequest = new UserInfoRequest(
            //     new URI(OIDCConfig.USER_INFO_ENDPOINT),
            //     (BearerAccessToken) accessToken);

            // HTTPResponse userInfoResponse = userInfoRequest.toHTTPRequest().send();
            // UserInfoResponse userInfoResponse = UserInfoResponse.parse(userInfoResponse);

            // Process user info, if needed
            // JSONObject userInfoJson = userInfoResponse.toSuccessResponse().getUserInfo().toJSONObject();

            String htmlFormatString = """
                    <!doctype html>
                                        
                    <html lang="en">
                                        
                      <head>
                        <meta charset="utf-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1">
                        <title>Base-bones OIDC</title>
                        <!-- You may want to add other icon formats and sizes, but have this at the least: -->
                        <link rel="shortcut icon" href="favicon.ico">
                        <link rel="stylesheet" href="your.css">
                      </head>
                                        
                      <body>
                        <main>
                            Access token:\s
                            <pre id="accessToken">%s</pre>\s
                            <br/>
                            ID token:\s
                            <pre id="idToken">%s</pre>
                        </main>
                        <script>
                        function decodeJWT(token) {
                            var payload = token.split('.')[1];
                            return JSON.stringify(JSON.parse(atob(payload)), null, 2);
                        }
                        
                        document.addEventListener('DOMContentLoaded', function () {
                            var accessTokenString = document.getElementById('accessToken').textContent;
                            var idTokenString = document.getElementById('idToken').textContent;
                            document.getElementById('accessToken').textContent = decodeJWT(accessTokenString);
                            document.getElementById('idToken').textContent = decodeJWT(idTokenString);
                        });
                        </script>
                        <noscript>
                          <!-- Optional, place it wherever it makes sense -->
                          JavaScript is not enabled.
                        </noscript>
                      </body>
                                        
                    </html>
                    """;

        return String.format(htmlFormatString, accessToken.getValue(), idToken.getParsedString());
    }

    private static String decode(String base64EncodedString) {
        byte[] decodedBytes = Base64.getDecoder().decode(base64EncodedString.split("\\.")[1]);
        return new String(decodedBytes, StandardCharsets.UTF_8);
    }

}
