package com.cgi.sharpe.a.david.barebonesoidc;

public class OIDCConfig {
    public static final String CLIENT_ID = "PRIMARY-CARE";
    public static final String CLIENT_SECRET = System.getenv("BAREBONESOIDC-SECRET");
    public static final String REDIRECT_URI = "http://localhost:8080/callback";
    public static final String AUTHORIZATION_ENDPOINT = "https://common-logon-test.hlth.gov.bc.ca/auth/realms/moh_applications/protocol/openid-connect/auth";
    public static final String TOKEN_ENDPOINT = "https://common-logon-test.hlth.gov.bc.ca/auth/realms/moh_applications/protocol/openid-connect/token";
    // Add other configuration parameters as needed
}
