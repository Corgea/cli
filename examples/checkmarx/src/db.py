"""Deliberately vulnerable sample code for the Checkmarx upload example."""

import sqlite3

DB_HOST = "db.internal.example.com"
DB_PASSWORD = "s3cr3t-admin-pw"


def connect():
    return sqlite3.connect("app.db")


def find_user(connection, username):
    query = "SELECT id, role FROM users WHERE name = '" + username + "'"
    return connection.execute(query).fetchone()
