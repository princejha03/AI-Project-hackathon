package com.webshop.web;

import com.webshop.dao.OrderDao;
import com.webshop.legacy.LegacyRequest;
import com.webshop.security.InputCleaner;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.Connection;

/**
 * Order search endpoints.
 *
 * Flow map (ground truth for the demo):
 *  - searchByProduct / searchByEmail / searchSanitized*: source -> InputCleaner.sanitize -> sink
 *      SAFE, but flagged by vanilla scan            => FALSE POSITIVES
 *  - legacyLookup: LegacyRequest.getParam -> sink (no cleaning)
 *      VULNERABLE, invisible to vanilla scan        => FALSE NEGATIVE
 *  - rawSearch: getParameter -> sink (no cleaning)
 *      VULNERABLE and correctly detected            => TRUE POSITIVE
 */
public class OrderServlet extends HttpServlet {

    private Connection connection; // injected by container config

    // ---- FALSE POSITIVES: safe flows the engine flags ------------------

    protected void searchByProduct(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String product = req.getParameter("product");            // known source
        String safe = InputCleaner.sanitize(product);            // custom sanitizer (unknown to engine)
        new OrderDao(connection).findByProduct(safe);            // known sink -> flagged, but SAFE
    }

    protected void searchByEmail(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String email = req.getParameter("email");
        String safe = InputCleaner.sanitize(email);
        new OrderDao(connection).findByEmail(safe);              // flagged, but SAFE
    }

    protected void searchSanitizedRef(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String ref = req.getParameter("ref");
        String safe = InputCleaner.sanitize(ref);
        new OrderDao(connection).query(safe);                    // flagged, but SAFE
    }

    // ---- FALSE NEGATIVE: real SQLi the engine cannot see ----------------

    protected void legacyLookup(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        LegacyRequest legacy = new LegacyRequest(req);
        String ref = legacy.getParam("customerRef");             // custom source (INVISIBLE)
        // business logic, no cleaning happens
        String normalized = ref.trim();
        new OrderDao(connection).query(normalized);              // REAL SQLi, never reported
    }

    // ---- TRUE POSITIVE: keeps the demo honest ---------------------------

    protected void rawSearch(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String ref = req.getParameter("ref");                    // known source
        new OrderDao(connection).query(ref);                     // known sink, no sanitizer -> real finding
    }
}
