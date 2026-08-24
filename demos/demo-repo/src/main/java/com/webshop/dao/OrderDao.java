package com.webshop.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/** Data access for orders. Statement.executeQuery is a KNOWN sink. */
public class OrderDao {

    private final Connection connection;

    public OrderDao(Connection connection) {
        this.connection = connection;
    }

    /**
     * Builds the SQL by string concatenation. If {@code customerRef} is
     * attacker-controlled and unsanitized, this is SQL injection.
     * (The planted false negative flows into this method via
     * LegacyRequest.getParam().)
     */
    public ResultSet query(String customerRef) throws SQLException {
        String sql = "SELECT * FROM orders WHERE customer_ref = '" + customerRef + "'";
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(sql); // SINK
    }

    public ResultSet findByProduct(String productName) throws SQLException {
        String sql = "SELECT * FROM orders WHERE product = '" + productName + "'";
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(sql); // SINK
    }

    public ResultSet findByEmail(String email) throws SQLException {
        String sql = "SELECT * FROM orders WHERE email = '" + email + "'";
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(sql); // SINK
    }
}
