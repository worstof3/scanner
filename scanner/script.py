"""
Main script for scanner.

Functions:
main -- Script function.
"""


from argparse import ArgumentParser, SUPPRESS
import asyncio
import logging
import os
import sqlite3
import sys
from functools import partial
from . import scanoperations


def main():
    """Script function."""
    # Parsing arguments.
    parser = ArgumentParser(description='Network scanner.')
    parser.add_argument('addresses', default=SUPPRESS, help='Addresses to scan.')
    parser.add_argument('period', default=SUPPRESS, help='Period of scan.')
    parser.add_argument('dbase_path', default=SUPPRESS, help='Path to database file.')
    parser.add_argument('-v', '--verbose', help='Verbose output.', action='store_true')
    args = parser.parse_args()

    # Checking root permissions (they are needed to send ARP packets.)
    euid = os.geteuid()
    if euid != 0:
        args = ['sudo', sys.executable] + sys.argv + [os.environ]
        os.execlpe('sudo', *args)

    # Logging config.
    logging_config = {'format': '%(asctime)s: %(message)s'}
    if args.verbose:
        logging_config['level'] = logging.INFO
    logging.basicConfig(**logging_config)

    # Initializing.
    loop = asyncio.get_event_loop()
    lock = asyncio.Lock()
    ending = asyncio.Future()
    scanner = partial(scanoperations.scan_arp, args.addresses)
    scanner_coro = partial(loop.run_in_executor, None, scanner)
    conn = sqlite3.connect(args.dbase_path)
    if not scanoperations.check_dbase(conn):
        scanoperations.init_dbase(conn)
    result_handler = partial(scanoperations.write_to_dbase, conn=conn, lock=lock)

    # Running scanner.
    try:
        scanning = scanoperations.scan_until_complete(loop, scanner_coro, result_handler, int(args.period), ending)
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
