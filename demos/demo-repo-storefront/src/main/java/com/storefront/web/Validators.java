package com.storefront.web;

/**
 * Custom HTML-encoding helper the engine has no built-in knowledge of --
 * exactly the kind of function TrueSignal is meant to learn.
 */
public final class Validators {

    private Validators() {
    }

    /** XSS: HTML-encodes the characters that let attacker input break out of markup. */
    public static String encodeHtml(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
