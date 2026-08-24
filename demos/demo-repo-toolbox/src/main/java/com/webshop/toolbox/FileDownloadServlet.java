package com.webshop.toolbox;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Planted ground truth for Path Traversal: one flow safe because of a
 * custom path sanitizer the engine can't see (a false positive once
 * flagged), one honest true positive with no sanitizer at all.
 */
public class FileDownloadServlet {

    protected void downloadReport(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("file");
        String safeName = Validators.sanitizePath(name);
        byte[] data = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("/var/reports", safeName));
        resp.getOutputStream().write(data);
    }

    protected void downloadRaw(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String path = req.getParameter("path");
        byte[] data = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path));
        resp.getOutputStream().write(data);
    }
}
