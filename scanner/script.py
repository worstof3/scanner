import sqlite3
import scapy.all


def connect(dbase):
    """
    Function connects to sqlite3 database and creates cursor.

    Args:
    dbase -- Path to database file.

    Returns:
    Tuple (connection, cursor).
    """
    conn = sqlite3.connect(dbase)
    cursor = conn.cursor()
    return conn, cursor


def scan_arp(addresses):
    """
    Function calls arping from scapy and returns information about active users.

    Args:
    addresses -- Range of addresses.

    Returns:
    Iterable of dictionaries with mac and ip addresses of users.
    """
    answers, _ = scapy.all.arping(addresses, verbose=False)
    users = (dict(mac=answer[1].getlayer(scapy.all.ARP).hwsrc, ip=answer[1].getlayer(scapy.all.ARP).psrc)
             for answer in answers)
    return users


async def scan_until_complete(loop, scanner, result_handler, period, ending):
    """
    Calls scanner periodically until ending is done.

    Args:
    loop -- Event loop.
    scanner -- Scanning coroutine function, it will be called without arguments.
    result_handler -- Coroutine function handling result of scanning, it will be called with return value of scanner.
    period -- Period of time (in seconds) after which coroutine will be called again.
    ending -- Asyncio future, if it's done coroutine won't be called again.
    """
    if not ending.done():
        next_time = scan_until_complete(loop, scanner, result_handler, period, ending)
        loop.call_later(period, loop.create_task, next_time)
        result = await scanner()
        await result_handler(result)


async def write_to_database(conn, users):
    """
    Write information in users to database.

    Args:
    conn -- Connection to database.
    users -- Dictionary with information.
    """
    cursor = conn.cursor()