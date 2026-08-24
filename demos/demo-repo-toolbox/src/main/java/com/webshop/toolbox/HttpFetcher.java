package com.webshop.toolbox;

/**
 * Issues an outbound HTTP request to an attacker-influenced URL if nothing
 * upstream validated the target host. Exactly what needs to be learned as
 * an SSRF sink once a flow is confirmed to reach it unchecked.
 */
public final class HttpFetcher {

    private HttpFetcher() {
    }

    public static String fetchRemote(String url) throws Exception {
        java.net.URL target = new java.net.URL(url);
        return new String(target.openStream().readAllBytes());
    }
}
