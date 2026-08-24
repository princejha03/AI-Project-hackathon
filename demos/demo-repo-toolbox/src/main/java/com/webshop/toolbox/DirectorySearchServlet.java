package com.webshop.toolbox;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Planted ground truth for LDAP Injection: one flow safe because of a
 * custom filter-escaping sanitizer the engine can't see (a false positive
 * once flagged), one honest true positive with no escaping at all.
 */
public class DirectorySearchServlet {

    protected void searchEmployees(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        String safeFilter = Validators.escapeLdap(name);
        LdapDirectory.searchDirectory("(cn=" + safeFilter + ")");
    }

    protected void searchRaw(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String filter = req.getParameter("filter");
        LdapDirectory.searchDirectory(filter);
    }
}
