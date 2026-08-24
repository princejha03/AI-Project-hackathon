package com.webshop.web;

import com.webshop.dao.OrderDao;
import com.webshop.security.InputCleaner;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.Connection;

/** More sanitized flows -> more false positives in the vanilla scan. */
public class ProfileServlet extends HttpServlet {

    private Connection connection;

    protected void ordersForUser(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String user = req.getParameter("user");
        String safe = InputCleaner.sanitize(user);
        new OrderDao(connection).query(safe);                 // SAFE, flagged
    }

    protected void ordersForAccount(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String acct = req.getParameter("account");
        String safe = InputCleaner.sanitizeNumeric(acct);
        new OrderDao(connection).query(safe);                 // SAFE, flagged
    }

    protected void searchHistory(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String term = req.getParameter("q");
        String safe = InputCleaner.sanitize(term);
        new OrderDao(connection).findByProduct(safe);         // SAFE, flagged
    }

    protected void contactLookup(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String mail = req.getParameter("mail");
        String safe = InputCleaner.sanitize(mail);
        new OrderDao(connection).findByEmail(safe);           // SAFE, flagged
    }
}
