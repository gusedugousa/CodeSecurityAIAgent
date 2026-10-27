"""Intentionally vulnerable sample Flask app used to exercise the security scanners in tests."""
import os
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "SuperSecretPassword123!"


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return str(cursor.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


@app.route("/eval")
def unsafe_eval():
    expr = request.args.get("expr")
    return str(eval(expr))


def load_config(path):
    return __import__("yaml").load(open(path), Loader=__import__("yaml").Loader)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
