"""Intentionally weak crypto helper for scanner test fixtures."""
import hashlib
import pickle


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def deserialize(data: bytes):
    return pickle.loads(data)


API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"
