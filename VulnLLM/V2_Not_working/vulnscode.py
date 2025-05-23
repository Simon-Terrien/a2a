import sqlite3
import html
import hashlib
import subprocess
import requests
import xml.etree.ElementTree as ET
import pickle
import threading
import time
import jwt  # PyJWT for JWT handling
import os
import logging

# Module: vulnerable_levels_complete.py
# Description: Module containing a range of vulnerabilities from simple to advanced,
# with dead code, unused functions, and unreachable branches for testing purposes.

logging.basicConfig(level=logging.INFO)

def _unused_helper():
    # Dead code: helper that is never called
    print("This function is never used")
    return None

class VulnerableLevelsComplete:
    """
    Class containing methods with vulnerabilities for testing scanners.

    Levels:
      - Level 1: Simple vulnerabilities (SQLi, XSS, command injection)
      - Level 2: Intermediate (time-based SQLi, XXE, SSRF, pickle deserialization)
      - Level 3: Advanced (JWT bypass, race condition, NoSQLi, logic flaws)

    Contains dead code, unreachable branches, and unused methods to simulate noise.
    """
    def __init__(self):
        # Setup in-memory SQLite database
        self.conn = sqlite3.connect(':memory:')
        self.cursor = self.conn.cursor()
        self.cursor.execute('CREATE TABLE Users (Username TEXT, Data TEXT)')
        self.cursor.execute('INSERT INTO Users VALUES ("admin", "secret_admin_data")')
        self.conn.commit()
        self.sessions = {}
        self.user_records = ["admin:secret", "user:password"]
        self.admin_password = "admin123"

        # Unreachable code example
        if False:
            self.cursor.execute('DROP TABLE Users')  # never executed

    # ========== Level 1: Simple ===========
    def l1_sql_injection(self, username):
        """SQL injection via string concatenation"""
        query = f"SELECT Data FROM Users WHERE Username = '{username}'"
        self.cursor.execute(query)
        return self.cursor.fetchone()

    def l1_xss(self, user_input):
        """Reflective XSS without encoding"""
        return f"<div>{user_input}</div>"

    def l1_cmd_injection(self, cmd):
        """Command injection via shell=True"""
        return subprocess.check_output(cmd, shell=True).decode()

    # Dead: duplicate function, never used
    def duplicate_unused(self, x):
        return x * 2

    # ========== Level 2: Intermediate ===========
    def l2_time_based_sqli(self, payload):
        """Blind SQLi time-based simulation"""
        start = time.time()
        try:
            self.cursor.execute(f"SELECT CASE WHEN ({payload}) THEN sqlite_version() END")
        except Exception:
            pass
        duration = time.time() - start
        return duration

    def l2_xxe(self, xml_str):
        """XXE via xml parser with entity resolution"""
        parser = ET.XMLParser()
        parser.entity = {}  # force vulnerability
        return ET.fromstring(xml_str, parser=parser)

    def l2_ssrf(self, url):
        """SSRF allowing file:// and http:// requests"""
        return requests.get(url).text

    def l2_pickle_deserialize(self, data_bytes):
        """Unsafe pickle deserialization"""
        return pickle.loads(data_bytes)

    # Unreachable variant
    def l2_unreachable_ssrf(self, url):
        if False:
            return requests.get(url).content
        return None

    # ========== Level 3: Advanced ===========
    def l3_jwt_no_verify(self, token):
        """JWT decode without signature verification"""
        return jwt.decode(token, options={"verify_signature": False})

    def l3_race_condition(self, filename):
        """Race condition on file write and delete"""
        def writer():
            with open(filename, 'w') as f:
                f.write("safe-data")
        def deleter():
            if os.path.exists(filename):
                os.remove(filename)
        t1 = threading.Thread(target=writer)
        t2 = threading.Thread(target=deleter)
        t1.start(); t2.start()
        t1.join(); t2.join()
        return os.path.exists(filename)

    def l3_nosql_injection(self, query_dict):
        """Simulated NoSQL injection via naive filter"""
        users = [
            {"user": "admin", "pwd": "secret"},
            {"user": "bob", "pwd": "pwd"}
        ]
        return [u for u in users if u['user'] == query_dict.get('user')]

    def l3_logic_flaw(self, role, action):
        """Business logic flaw: superadmin bypass"""
        permissions = {"user": ["read"], "admin": ["read", "write", "delete"]}
        # Unchecked role
        if role == "superadmin":
            return True
        return action in permissions.get(role, [])

    # ========== Additional vulnerabilities ===========
    def sql_bulk_query(self, usernames):
        """Multiple SQL queries in one call"""
        query = ";".join([f"SELECT Data FROM Users WHERE Username = '{u}'" for u in usernames])
        return self.cursor.executescript(query)

    def insecure_hash_md5(self, password):
        """Weak MD5 hash"""
        return hashlib.md5(password.encode()).hexdigest()

    def insecure_hash_sha1(self, data):
        """Weak SHA1 hash, dead code example"""
        if False:
            return hashlib.sha1(data.encode()).hexdigest()
        return None

    # Unused and dead code
    def _private_unused(self):
        raise NotImplementedError("Not implemented")

    def unreachable_cleanup(self):
        # This block is never reached
        if 1 == 0:
            os.remove('important.txt')

if __name__ == "__main__":
    vl = VulnerableLevelsComplete()
    # Level 1 tests
    print(vl.l1_sql_injection("admin'; -- "))
    print(vl.l1_xss("<script>alert(1)</script>"))
    print(vl.l1_cmd_injection("echo Hello"))

    # Level 2 tests
    delay = vl.l2_time_based_sqli("1=1 OR (SELECT sleep(2))")
    print(f"Delay: {delay}")
    # print(vl.l2_xxe('<?xml version="1.0"?><!DOCTYPE a [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'))
    # print(vl.l2_ssrf("file:///etc/hosts"))

    # Level 3 tests
    token = jwt.encode({"user": "admin"}, key="secret_key")
    print(vl.l3_jwt_no_verify(token))
    print(f"Race exists: {vl.l3_race_condition('race_test.txt')}")
    print(vl.l3_nosql_injection({"user": {"$ne": ""}}))
    print(f"Logic bypass: {vl.l3_logic_flaw('superadmin', 'delete')}")
