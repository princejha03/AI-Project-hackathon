package com.storefront.web;

/**
 * The risky actions StoreFrontServlet's request handlers feed straight
 * into. Real code would sit behind these calls; keeping each body a
 * genuine (if abbreviated) statement -- rather than just a comment -- means
 * the audit page's resolved code panel actually shows something to review.
 */
public final class Sinks {

    private Sinks() {
    }

    public static void applyAccountChange(String value) {
        accountDao.updateShippingAddress(value); // persisted immediately, no CSRF token was checked upstream
    }

    public static void renderUnescaped(String html) {
        responseWriter.print(html); // written to the response exactly as received, no encoding
    }

    public static void redirectTo(String url) {
        response.sendRedirect(url); // no allow-list check against this app's own domains
    }

    public static void finalizeResponseWithoutCsp(String theme) {
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("X-Theme", theme);
        // Content-Security-Policy is never one of the headers this method sets
    }

    public static void renderExternalLink(String url) {
        // no rel="noopener noreferrer" -- the opened page keeps a window.opener handle back to us
        responseWriter.print("<a href=\"" + url + "\" target=\"_blank\">Visit partner</a>");
    }

    public static void loadClientScript(String path) {
        responseWriter.print("<script src=\"" + path + "\"></script>");
    }

    public static void renderLegacyWidget(String id) {
        // jQuery 1.9/3.0 removed both $.browser and .live() -- still called here
        responseWriter.print("<script>if ($.browser.msie) { $('#banner-" + id
                + "').live('click', showPromo); }</script>");
    }
}
