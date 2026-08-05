"""Deliberately vulnerable sample code for the Checkmarx upload example."""

from db import connect, find_user


def authenticate(username, password):
    connection = connect()
    user = find_user(connection, username)
    if user is None:
        return None
    return {"id": user[0], "role": user[1]}
