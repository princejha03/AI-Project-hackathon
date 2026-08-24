package com.webshop.toolbox;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Planted ground truth for Cross-Site Scripting: one flow safe because of
 * a custom HTML-encoding sanitizer the engine can't see (a false positive
 * once flagged), one honest true positive with no encoding at all.
 */
public class CommentServlet {

    protected void renderComment(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String comment = req.getParameter("comment");
        String safeComment = Validators.encodeHtml(comment);
        HtmlRenderer.renderUnescaped("<div class=\"comment\">" + safeComment + "</div>");
    }

    protected void renderRawComment(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String comment = req.getParameter("raw");
        HtmlRenderer.renderUnescaped("<div class=\"comment\">" + comment + "</div>");
    }
}
