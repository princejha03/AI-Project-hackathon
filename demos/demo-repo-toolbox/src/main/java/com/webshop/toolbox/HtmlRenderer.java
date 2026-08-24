package com.webshop.toolbox;

/**
 * Writes markup straight to the response body. TrueSignal has no built-in
 * knowledge of this class -- exactly what needs to be learned as an XSS
 * sink once a flow is confirmed to reach it unencoded.
 */
public final class HtmlRenderer {

    private HtmlRenderer() {
    }

    public static void renderUnescaped(String html) {
        System.out.println(html);
    }
}
