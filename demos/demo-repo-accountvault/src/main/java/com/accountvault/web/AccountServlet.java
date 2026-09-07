package com.accountvault.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Account and session handling for the AccountVault demo -- each method
 * below plants one server-hardening gap TrueSignal is meant to find (see
 * scanner.py's _SINK_CLASSES for what each Sinks call stands in for).
 */
public class AccountServlet {

    // Insufficiently Protected Credentials: the raw password is persisted
    // with no hashing in between.
    protected void registerAccount(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String password = req.getParameter("password");
        Sinks.persistCredential(password);
    }

    // Missing HSTS Header: the requested locale is honored, but the
    // response this method sends never sets Strict-Transport-Security.
    protected void applyLocale(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String locale = req.getParameter("locale");
        Sinks.finalizeResponseWithoutHsts(locale);
    }

    // Trust Boundary Violation (Session Variable): an unvalidated request
    // parameter crosses straight into the trusted session scope.
    protected void impersonateSupportAgent(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String agentId = req.getParameter("agentId");
        Sinks.storeInSession(agentId);
    }

    // Heap Inspection: the security answer is kept in an ordinary
    // (immutable, GC-lingering) String instead of a char[] that can be
    // wiped after use.
    protected void recordSecurityAnswer(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String answer = req.getParameter("securityAnswer");
        Sinks.cacheInMemory(answer);
    }

    // Use of a Broken or Risky Cryptographic Algorithm: the new password is
    // protected with a fast, collision-prone digest instead of a proper KDF.
    protected void resetPassword(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String newPassword = req.getParameter("newPassword");
        Sinks.encryptWithLegacyCipher(newPassword);
    }
}
