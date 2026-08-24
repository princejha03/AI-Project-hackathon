package com.webshop.toolbox;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Planted ground truth for SSRF: one flow safe because of a custom host
 * allow-list the engine can't see (a false positive once flagged), one
 * honest true positive with no allow-list at all.
 */
public class WebhookServlet {

    protected void fetchPreview(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String target = req.getParameter("url");
        String safeUrl = Validators.validateUrl(target);
        HttpFetcher.fetchRemote(safeUrl);
    }

    protected void fetchRawUrl(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String target = req.getParameter("target");
        HttpFetcher.fetchRemote(target);
    }
}
