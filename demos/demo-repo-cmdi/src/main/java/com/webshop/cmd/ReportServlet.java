package com.webshop.cmd;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Planted ground truth for the Command Injection demo, mirroring the
 * structure of the SQL Injection demo in demo-repo/: one flow that is
 * actually safe because of a custom sanitizer the engine can't see
 * (a false positive once flagged), and one honest true positive with no
 * sanitizer at all.
 */
public class ReportServlet {

    protected void generateReport(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String format = req.getParameter("format");
        String safeFormat = FormatValidator.clean(format);
        Runtime.getRuntime().exec("report-tool --format=" + safeFormat);
    }

    protected void generateRaw(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String command = req.getParameter("cmd");
        Runtime.getRuntime().exec(command);
    }
}
