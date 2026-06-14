from contextlib import contextmanager

from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, ServiceUnavailable

from . import config

_driver = None


def get_driver():
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            config.NEO4J_URI,
            auth=(config.NEO4J_USER, config.NEO4J_PASSWORD),
        )
    return _driver


@contextmanager
def session():
    driver = get_driver()
    sess = driver.session()
    try:
        yield sess
    finally:
        sess.close()


def is_available() -> bool:
    """
    Cheap connectivity check used to decide real-DB vs. seed-data
    fallback. Fails fast (no retries) if Neo4j isn't up yet.
    """
    try:
        driver = get_driver()
        driver.verify_connectivity()
        return True
    except (ServiceUnavailable, AuthError, OSError):
        return False
