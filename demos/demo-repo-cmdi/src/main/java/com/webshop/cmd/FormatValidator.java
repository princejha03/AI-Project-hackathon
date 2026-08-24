package com.webshop.cmd;

/**
 * Custom allow-list filter for report format names. Effective against
 * command injection, but the engine has no built-in knowledge of it --
 * exactly the kind of function TrueSignal is meant to learn.
 */
public final class FormatValidator {

    private FormatValidator() {
    }

    public static String clean(String input) {
        if (input == null) {
            return "pdf";
        }
        StringBuilder out = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (Character.isLetterOrDigit(c)) {
                out.append(c);
            }
        }
        return out.length() == 0 ? "pdf" : out.toString();
    }
}
