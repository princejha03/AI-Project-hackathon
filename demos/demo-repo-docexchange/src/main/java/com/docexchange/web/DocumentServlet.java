package com.docexchange.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Document upload/export handling for the DocExchange demo -- each method
 * below plants one data-handling bug TrueSignal is meant to find (see
 * scanner.py's _SINK_CLASSES for what each Sinks call stands in for).
 */
public class DocumentServlet {

    // Path Traversal: the requested filename is used to read a file with
    // no "../" restriction.
    protected void downloadAttachment(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String filename = req.getParameter("file");
        Sinks.readAllBytes(filename);
    }

    // Improper Restriction of XXE Reference: the uploaded XML manifest is
    // parsed with external entities still enabled.
    protected void importManifest(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String xml = req.getParameter("manifest");
        Sinks.parseUntrustedXml(xml);
    }

    // Log Forging: the requested document id is written straight into the
    // audit log with no newline/control-character stripping, letting an
    // attacker inject fake log lines.
    protected void logDownloadRequest(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String docId = req.getParameter("docId");
        Sinks.writeAuditLog(docId);
    }

    // Privacy Violation: the customer's tax ID is exported into a
    // shareable report with no masking or access check.
    protected void exportCustomerReport(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String taxId = req.getParameter("taxId");
        Sinks.exportProfileData(taxId);
    }
}
