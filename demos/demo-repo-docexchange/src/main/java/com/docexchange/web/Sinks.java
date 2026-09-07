package com.docexchange.web;

import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * The risky actions DocumentServlet's request handlers feed straight into.
 * Real code would sit behind these calls; keeping each body a genuine (if
 * abbreviated) statement -- rather than just a comment -- means the audit
 * page's resolved code panel actually shows something to review.
 */
public final class Sinks {

    private Sinks() {
    }

    public static void readAllBytes(String path) throws Exception {
        Files.readAllBytes(Paths.get(path)); // path taken from the request, no "../" restriction
    }

    public static void parseUntrustedXml(String xml) throws Exception {
        // external-entity resolution is never disabled on this factory
        xmlDocumentBuilder.parse(xml);
    }

    public static void writeAuditLog(String value) {
        logger.info("download requested: " + value); // no newline/control-character stripping first
    }

    public static void exportProfileData(String value) {
        reportBuilder.append("Tax ID: " + value); // written into the shareable report as-is, no masking
    }
}
