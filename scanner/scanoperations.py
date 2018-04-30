"""
Module defines functions for scanning and writing results to database.

Functions:
check_dbase -- Check if database contains tables users and times.
init_dbase -- Create tables users and times.
write_to_dbase -- Write results of scan to database.
scan_arp -- Call arping from scapy and return information about active users.
scan_until_complete -- Call scanner periodically.
"""
import logging
from datetime import datetime
from scapy.all import arping, ARP


def check_dbase(conn):
    """
    Check if database contains tables users and times.

    Args:
    conn -- Connection to database.
    """
    logging.info('Checking database.')
    cursor = conn.cursor()

    cursor.execute("""
    SELECT name
    FROM sqlite_master
    WHERE type = 'table'
    """)
    tables = cursor.fetchall()
    if ('users', ) in tables and ('times', ) in tables:
        logging.info('Database has users and times tables.')
        return True
    else:
        logging.info("Database doesn't have users or times table.")
        return False


def init_dbase(conn):
    """
    Create tables users and times.

    Args:
    conn -- Connection with database.
    cursor -- Cursor from connection.
    """
    logging.info('Creating users and times tables.')
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE users(
    mac TEXT PRIMARY KEY,
    name TEXT)
    """)
    cursor.execute("""
    CREATE TABLE times(
    mac TEXT,
    ip TEXT,
    time TEXT,
    FOREIGN KEY(mac) REFERENCES users(mac))
    """)

    conn.commit()


async def write_to_dbase(result, conn, lock):
    """
    Write results of scan to database.

    Args:
    result -- Result of scan.
    conn -- Connection to database.
    lock -- Lock on database.
    """
    cursor = conn.cursor()
    logging.info('Writing results to database.')

    async with lock:
        cursor.execute("""
        SELECT *
        FROM users
        """)
        known_users = dict(cursor.fetchall())
        users_count = len(known_users)
        for mac, ip in result['users'].items():
            # Writing new users to table users.
            if mac not in known_users:
                cursor.execute("""
                INSERT INTO users
                VALUES(?, ?)
                """, (mac, f'new_user_{users_count}'))
                users_count += 1

            # Writing results of scan to table times.
            cursor.execute("""
            INSERT INTO times
            VALUES(?, ?, ?)
            """, (mac, ip, result['date']))

        conn.commit()


def scan_arp(addresses):
    """
    Call arping from scapy and return information about active users.

    Args:
    addresses -- Range of addresses.

    Returns:
    Dictionary with users info (key users) and date of scan (key date).
    """
    logging.info('Starting scanning.')

    answers, _ = arping(addresses, verbose=False)
    logging.info('Ended scanning.')
    date = datetime.today()
    datestring = date.isoformat(' ', 'seconds')
    users = {}
    for answer in answers:
        users[answer[1].getlayer(ARP).hwsrc] = answer[1].getlayer(ARP).psrc
    return {'users': users, 'date': datestring}


async def scan_until_complete(loop, scanner, result_handler, period, ending):
    """
    Call scanner periodically until ending is done.

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
