from argparse import ArgumentParser, SUPPRESS
import asyncio
import configparser
import logging
import os
import sqlite3
import sys
from datetime import datetime
from functools import partial
from scapy.all import arping, ARP
"""
Todo:

Handling database file and date of last scan.
Tests.
"""


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
    logging.info('Starting scanning.')
    answers, _ = arping(addresses, verbose=False)
    logging.info('Ended scanning.')
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


async def write_to_database(users, conn, last_date, lock):
    """
    Write information in users to database.

    Args:
    conn -- Connection to database.
    users -- Dictionary with information.
    last_date -- Date of last scan.
    """
    cursor = conn.cursor()
    async with lock:
        logging.info('Writing results to database.')
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
        cursor.execute("""
        SELECT *
        FROM users
        """)
        known_users = dict(cursor.fetchall())
        users_count = len(known_users)
        for mac, user in users.items():
            if mac not in known_users:
                cursor.execute("""
                INSERT INTO users
                VALUES(?, ?)
                """, (mac, f'new_user_{users_count}'))
                users_count += 1
            cursor.execute("""
            INSERT INTO times
            VALUES(?, ?, ?, ?)
            """, (mac, user['ip'], user['date'], None))
        conn.commit()


def main():
    euid = os.geteuid()
    if euid != 0:
        args = ['sudo', sys.executable] + sys.argv + [os.environ]
        os.execlpe('sudo', *args)
    parser = ArgumentParser(description='Network scanner.')
    parser.add_argument('addresses', default=SUPPRESS, help='Addresses to scan.')
    parser.add_argument('period', default=SUPPRESS, help='Period of scan.')
    parser.add_argument('-c', '--config', default='scanner.ini', help='Path to config file.')
    parser.add_argument('-v', '--verbose', help='Verbose output.', action='store_true')
    args = parser.parse_args()

    logging_config = {'format': '%(asctime)s: %(message)s'}
    if args.verbose:
        logging_config['level'] = logging.INFO
    logging.basicConfig(**logging_config)

    loop = asyncio.get_event_loop()
    lock = asyncio.Lock()
    ending = asyncio.Future()
    scanner = partial(scan_arp, args.addresses)
    scanner_coro = partial(loop.run_in_executor, None, scanner)
    config = configparser.ConfigParser()
    config.read(args.config)
    conn = sqlite3.connect(config['DEFAULT']['database'])
    if not check_dbase(conn):
        init_dbase(conn)
    result_handler = partial(write_to_database, conn=conn, last_date=datetime(2018, 4, 28, 3, 23, 0), lock=lock)

    try:
        scanning = scan_until_complete(loop, scanner_coro, result_handler, int(args.period), ending)
        loop.run_until_complete(scanning)
        loop.run_forever()
    except KeyboardInterrupt:
        ending.set_result(True)
        tasks = asyncio.Task.all_tasks()
        logging.info('Closing program, finishing scheduled tasks.')
        loop.run_until_complete(asyncio.gather(*tasks))
        logging.info('All tasks finished.')


if __name__ == '__main__':
    main()