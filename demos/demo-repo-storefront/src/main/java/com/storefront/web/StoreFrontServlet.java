package com.storefront.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Front-of-store request handling for the StoreFront demo -- each method
 * below plants one client-facing vulnerability TrueSignal is meant to find
 * (see scanner.py's _SINK_CLASSES for what each Sinks call stands in for).
 */
public class StoreFrontServlet {

    // CSRF: a state-changing action with no anti-CSRF token check.
    protected void updateShippingAddress(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String address = req.getParameter("address");
        Sinks.applyAccountChange(address);
    }

    // Reflected XSS: the search term is rendered back into the page unescaped.
    protected void renderSearchResults(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String term = req.getParameter("q");
        Sinks.renderUnescaped("<div class=\"results\">" + term + "</div>");
    }

    // Reflected XSS, safe: the same flow through a custom HTML-encoding
    // sanitizer the engine can't see -- a false positive once flagged.
    protected void renderSearchResultsSafe(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String term = req.getParameter("q");
        String safeTerm = Validators.encodeHtml(term);
        Sinks.renderUnescaped("<div class=\"results\">" + safeTerm + "</div>");
    }

    // Open Redirect: the post-checkout return URL is taken straight from
    // the request and redirected to with no allow-list check.
    protected void handleCheckoutReturn(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String returnUrl = req.getParameter("returnUrl");
        Sinks.redirectTo(returnUrl);
    }

    // Missing CSP Header: the requested theme is honored, but the response
    // this method sends never includes a Content-Security-Policy header.
    protected void applyTheme(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String theme = req.getParameter("theme");
        Sinks.finalizeResponseWithoutCsp(theme);
    }

    // Unsafe use of target="_blank": the partner link is rendered with
    // target="_blank" and no rel="noopener noreferrer", letting the opened
    // page reach back into this one via window.opener.
    protected void renderPartnerLink(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String partnerUrl = req.getParameter("partnerUrl");
        Sinks.renderExternalLink(partnerUrl);
    }

    // Client Dangerous File Inclusion: a widget script path taken from the
    // request is injected straight into a <script src="..."> tag.
    protected void loadWidget(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String widgetPath = req.getParameter("widget");
        Sinks.loadClientScript(widgetPath);
    }

    // Client jQuery Deprecated Symbols: the legacy promo banner still calls
    // $.browser and .live(), both removed since jQuery 1.9/3.0.
    protected void renderLegacyPromoBanner(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String bannerId = req.getParameter("bannerId");
        Sinks.renderLegacyWidget(bannerId);
    }
}
