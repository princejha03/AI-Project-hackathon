package com.accountvault.web;

import java.security.MessageDigest;

/**
 * The risky actions AccountServlet's request handlers feed straight into.
 * Real code would sit behind these calls; keeping each body a genuine (if
 * abbreviated) statement -- rather than just a comment -- means the audit
 * page's resolved code panel actually shows something to review.
 */
public final class Sinks {

    private Sinks() {
    }

    public static void persistCredential(String value) {
        credentialRepository.save(value); // saved as-is -- no hashing or salting before this call
    }

    public static void finalizeResponseWithoutHsts(String locale) {
        response.setHeader("Content-Language", locale);
        response.setHeader("X-Frame-Options", "DENY");
        // Strict-Transport-Security is never one of the headers this method sets
    }

    public static void storeInSession(String value) {
        session.setAttribute("agentId", value); // no validation before crossing into the trusted session scope
    }

    public static void cacheInMemory(String value) {
        // kept as an ordinary String -- lingers on the heap until GC, can't be wiped like a char[]
        securityAnswerCache.put(sessionId(), value);
    }

    public static void encryptWithLegacyCipher(String value) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5"); // broken for password storage
        digest.update(value.getBytes());
    }
}
