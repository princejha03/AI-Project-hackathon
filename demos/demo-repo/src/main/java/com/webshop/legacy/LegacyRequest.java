package com.webshop.legacy;

import javax.servlet.http.HttpServletRequest;

/**
 * Legacy adapter from the 2016 framework migration. Wraps the servlet
 * request so old code didn't have to change signatures.
 *
 * Every value returned here is attacker-controlled user input, but the
 * SAST engine only knows HttpServletRequest.getParameter() as a taint
 * source. Because the tainted data enters through THIS wrapper, the
 * engine considers it clean -> flows from here are invisible
 * (false negatives).
 */
public class LegacyRequest {

    private final HttpServletRequest inner;

    public LegacyRequest(HttpServletRequest inner) {
        this.inner = inner;
    }

    /** Returns raw, unvalidated user input. TAINT SOURCE (unknown to engine). */
    public String getParam(String name) {
        String value = inner.getParameter(name);
        return value != null ? value : "";
    }

    /** Also a taint source: raw header access through the wrapper. */
    public String getHeaderValue(String name) {
        String value = inner.getHeader(name);
        return value != null ? value : "";
    }
}
