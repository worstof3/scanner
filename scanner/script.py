import os.path
from datetime import datetime
from sqlite3 import connect
from scapy.all import arping, ARP


# def connect_dbase(dbase):
#     """
#     Function connects to sqlite3 database and creates cursor.
#
#     Args:
#     dbase -- Path to database file.
#
#     Returns:
#     Tuple (connection, cursor).
#     """
#     conn = connect(dbase)
#     cursor = conn.cursor()
#     return conn, cursor


def init_dbase(conn):
    """
    Create tables users and times.

    Args:
    conn -- Connection with database.
    cursor -- Cursor from connection.
    """
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE users(
    id TEXT PRIMARY KEY,
    mac TEXT)
    """)
    cursor.execute("""
    CREATE TABLE times(
    mac TEXT,
    ip TEXT,
    enter_time TEXT,
    exit_time TEXT,
    FOREIGN KEY(mac) REFERENCES users(mac))
    """)

    conn.commit()


def scan_arp(addresses):
    """
    Function calls arping from scapy and returns information about active users.

    Args:
    addresses -- Range of addresses.

    Returns:
    Iterable of dictionaries with mac and ip addresses of users.
    """
    answers, _ = arping(addresses, verbose=False)
    date = datetime.today()
    users = {}
    for answer in answers:
        users[answer[1].getlayer(ARP).hwsrc] = dict(ip=answer[1].getlayer(ARP).psrc,
                                                    date=date.isoformat(' ', 'seconds'))
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


async def write_to_database(conn, users, last_date):
    """
    Write information in users to database.

    Args:
    conn -- Connection to database.
    users -- Dictionary with information.
    last_date -- Date of last scan.
    """
    cursor = conn.cursor()
    cursor.execute("""
    SELECT *
    FROM times
    WHERE exit_time IS NULL
    """)
    last_active = cursor.fetchall()
    left_macs = []
    for mac, ip, enter_time, exit_time in last_active:
        if mac in users:
            del users[mac]
        else:
            left_macs.append(mac)
    place_string = '(' + ', '.join(len(left_macs)*'?') + ')'
    cursor.execute("""
    UPDATE times
    SET exit_time = ?
    WHERE mac IN {} AND exit_time IS NULL
    """.format(place_string), (last_date, *left_macs))
    for mac, user in users.items():
        cursor.execute("""
        INSERT INTO times
        VALUES(?, ?, ?, ?)
        """, (mac, user['ip'], user['ip'], user['date'], None))
