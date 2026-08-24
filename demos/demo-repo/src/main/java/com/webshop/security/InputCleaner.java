package com.webshop.security;

/**
 * Company-standard input sanitizer, written in-house in 2019.
 * Strict allow-list approach: anything outside [a-zA-Z0-9 _.@-] is dropped,
 * single quotes are removed entirely, and length is capped.
 *
 * This IS an effective sanitizer against SQL injection for our query styles,
 * but the SAST engine has never heard of it -> every flow through it
 * is flagged as vulnerable (false positive).
 */
public final class InputCleaner {

    private static final int MAX_LEN = 256;

    private InputCleaner() {}

    /** Neutralizes SQLi metacharacters via strict allow-listing. */
    public static String sanitize(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(Math.min(input.length(), MAX_LEN));
        for (char c : input.toCharArray()) {
            if (out.length() >= MAX_LEN) break;
            if (Character.isLetterOrDigit(c) || c == ' ' || c == '_'
                    || c == '.' || c == '@' || c == '-') {
                out.append(c);
            }
            // quotes, semicolons, comment markers, etc. are dropped
        }
        return out.toString().trim();
    }

    /** Numeric-only variant used for ids and quantities. */
    public static String sanitizeNumeric(String input) {
        if (input == null) return "0";
        String digits = input.replaceAll("[^0-9]", "");
        return digits.isEmpty() ? "0" : digits;
    }
}
