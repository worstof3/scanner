import asyncio
import asynctest
import pickle
import sqlite3
import unittest
from unittest.mock import Mock, patch, ANY
from datetime import datetime
from .. import scanoperations


class TestDatabase(unittest.TestCase):
    def test_check_dbase(self):
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()

        self.assertFalse(scanoperations.check_dbase(conn))

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
        self.assertTrue(scanoperations.check_dbase(conn))

        conn.close()

    def test_init_dbase(self):
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        scanoperations.init_dbase(conn)

        cursor.execute("""
        PRAGMA table_info(users)
        """)
        table = cursor.fetchall()
        real_table = [(0, 'mac', 'TEXT', 0, None, 1), (1, 'name', 'TEXT', 0, None, 0)]
        self.assertEqual(table, real_table)

        cursor.execute("""
        PRAGMA table_info(times)
        """)
        table = cursor.fetchall()
        real_table = [(0, 'mac', 'TEXT', 0, None, 0), (1, 'ip', 'TEXT', 0, None, 0), (2, 'time', 'TEXT', 0, None, 0)]
        self.assertEqual(table, real_table)

    def test_write_to_dbase(self):
        loop = asyncio.new_event_loop()
        conn = sqlite3.connect(':memory:')
        scanoperations.init_dbase(conn)
        cursor = conn.cursor()
        lock = asyncio.Lock()
        result = {
            'users': {
                'ff:ff:ff:ff:ff:ff': '255.255.255.255',
                'aa:aa:aa:aa:aa:aa': '0.0.0.0'
            },
            'date': '2018-04-28 00:44:01'
        }
        loop.run_until_complete(scanoperations.write_to_dbase(result, conn, lock))
        cursor.execute("""
        SELECT *
        FROM users
        ORDER BY name
        """)
        users = cursor.fetchall()
        real_result = [('ff:ff:ff:ff:ff:ff', 'new_user_0'), ('aa:aa:aa:aa:aa:aa', 'new_user_1')]
        self.assertEqual(users, real_result)

        cursor.execute("""
        SELECT *
        FROM times
        ORDER BY mac
        """)
        times = cursor.fetchall()
        real_result = [('aa:aa:aa:aa:aa:aa', '0.0.0.0', '2018-04-28 00:44:01'),
                       ('ff:ff:ff:ff:ff:ff', '255.255.255.255', '2018-04-28 00:44:01')]
        self.assertEqual(times, real_result)

        result = {
            'users': {
                'ff:ff:ff:ff:ff:ff': '255.255.255.255'
            },
            'date': '2018-04-30 01:44:01'
        }
        loop.run_until_complete(scanoperations.write_to_dbase(result, conn, lock))
        cursor.execute("""
        SELECT *
        FROM users
        ORDER BY name
        """)
        users = cursor.fetchall()
        real_result = [('ff:ff:ff:ff:ff:ff', 'new_user_0'), ('aa:aa:aa:aa:aa:aa', 'new_user_1')]
        self.assertEqual(users, real_result)

        cursor.execute("""
        SELECT *
        FROM times
        ORDER BY mac, datetime(time)
        """)
        times = cursor.fetchall()
        real_result = [('aa:aa:aa:aa:aa:aa', '0.0.0.0', '2018-04-28 00:44:01'),
                       ('ff:ff:ff:ff:ff:ff', '255.255.255.255', '2018-04-28 00:44:01'),
                       ('ff:ff:ff:ff:ff:ff', '255.255.255.255', '2018-04-30 01:44:01')]
        self.assertEqual(times, real_result)

        loop.close()


class TestScan(unittest.TestCase):
    def test_scan_arp(self):
        """Test if correct iterable is returned."""
        # Pickled response from scanning.
        pickled_answers = (
            b'\x80\x03cscapy.layers.l2\nEther\nq\x00)Rq\x01C*\xff\xff\xff\xff\xff\xff\xa4\x171\xe8\xa0+'
            b'\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xa4\x171\xe8\xa0+\xff\xff\xff\xff\x00\x00\x00\x00'
            b'\x00\x00\xff\xff\xff\xffq\x02\x85q\x03bh\x00)Rq\x04C*\xa4\x171\xe8\xa0+\xff\xff\xff\xff\xff\xff'
            b'\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xa4\x171\xe8\xa0'
            b'+\xff\xff\xff\xffq\x05\x85q\x06b\x86q\x07.',
            b'\x80\x03cscapy.layers.l2\nEther\nq\x00)Rq\x01C*\xaa\xaa\xaa\xaa\xaa\xaa\xa4\x171\xe8\xa0+\x08\x06'
            b'\x00\x01\x08\x00\x06\x04\x00\x01\xa4\x171\xe8\xa0+\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\xc0\xa8'
            b'\x00\x14q\x02\x85q\x03bh\x00)Rq\x04C<\xa4\x171\xe8\xa0+\xaa\xaa\xaa\xaa\xaa\xaa\x08\x06\x00\x01\x08'
            b'\x00\x06\x04\x00\x02\xaa\xaa\xaa\xaa\xaa\xaa\xff\xff\xff\xff\xa4\x171\xe8\xa0+\xff\xff\xff\xff\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00q\x05\x85q\x06b\x86q\x07.')
        answers = tuple(pickle.loads(p) for p in pickled_answers)
        with patch('scanner.scanoperations.arping', Mock(return_value=(answers, b''))),\
             patch('scanner.scanoperations.datetime') as mock_datetime:
            mock_datetime.today.return_value = datetime(2018, 4, 28, 0, 44, 1, 123)
            users = scanoperations.scan_arp('address_range')
            real_result = {
                'users': {
                    'ff:ff:ff:ff:ff:ff': '255.255.255.255',
                    'aa:aa:aa:aa:aa:aa': '255.255.255.255'
                },
                'date': '2018-04-28 00:44:01'
            }
            self.assertDictEqual(users, real_result)

    def test_scan_until_complete(self):
        """Test if handler is called with return value of scanner and if scan is scheduled after period."""
        loop = asyncio.new_event_loop()
        mock_scanner = asynctest.CoroutineMock()
        mock_return = Mock()
        mock_scanner.return_value = mock_return
        mock_handler = asynctest.CoroutineMock()
        period = 2
        ending = asyncio.Future()

        loop.call_later(1, ending.set_result, True)
        with patch.object(loop, 'call_later') as mock_call_later:
            scanning = scanoperations.scan_until_complete(loop, mock_scanner, mock_handler, period, ending)
            loop.run_until_complete(scanning)
            mock_handler.assert_called_with(mock_return)
            mock_call_later.assert_called_with(period, ANY, ANY)

        loop.close()
