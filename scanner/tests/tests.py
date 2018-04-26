import asyncio
import asynctest
import pickle
import unittest
from unittest.mock import Mock, patch
from .. import script


class Tests(unittest.TestCase):
    def test_connect(self):
        """Test if correct functions are called and correct tuple is returned."""
        with patch('sqlite3.connect') as mock_connect:
            mock_connection, mock_cursor = Mock(), Mock()
            mock_connect.return_value = mock_connection
            mock_connection.cursor.return_value = mock_cursor
            result = script.connect('database')

            mock_connect.assert_called_with('database')
            mock_connection.cursor.assert_called()
            self.assertTupleEqual(result, (mock_connection, mock_cursor))

    def test_scan_arp(self):
        """Test if correct iterable is returned."""
        # Pickled response from scanning.
        pickled_answers = (
            b'\x80\x03cscapy.layers.l2\nEther\nq\x00)Rq\x01C*\xff\xff\xff\xff\xff\xff\xa4\x171\xe8\xa0+'
            b'\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xa4\x171\xe8\xa0+\xff\xff\xff\xff\x00\x00\x00\x00'
            b'\x00\x00\xff\xff\xff\xffq\x02\x85q\x03bh\x00)Rq\x04C*\xa4\x171\xe8\xa0+\xff\xff\xff\xff\xff\xff'
            b'\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xa4\x171\xe8\xa0'
            b'+\xff\xff\xff\xffq\x05\x85q\x06b\x86q\x07.',
            b'\x80\x03cscapy.layers.l2\nEther\nq\x00)Rq\x01C*\xff\xff\xff\xff\xff\xff\xa4\x171\xe8\xa0+\x08\x06'
            b'\x00\x01\x08\x00\x06\x04\x00\x01\xa4\x171\xe8\xa0+\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\xc0\xa8'
            b'\x00\x14q\x02\x85q\x03bh\x00)Rq\x04C<\xa4\x171\xe8\xa0+\xff\xff\xff\xff\xff\xff\x08\x06\x00\x01\x08'
            b'\x00\x06\x04\x00\x02\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xa4\x171\xe8\xa0+\xff\xff\xff\xff\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00q\x05\x85q\x06b\x86q\x07.')
        answers = tuple(pickle.loads(p) for p in pickled_answers)
        with patch('scapy.all.arping', Mock(return_value=(answers, b''))):
            users = script.scan_arp('address_range')
            real_result = (
                {'mac': 'ff:ff:ff:ff:ff:ff', 'ip': '255.255.255.255'},
                {'mac': 'ff:ff:ff:ff:ff:ff', 'ip': '255.255.255.255'},
            )
            self.assertTupleEqual(tuple(users), real_result)

    def test_scan_until_complete(self):
        """Test if handler is called with return value of scanner."""
        loop = asyncio.get_event_loop()
        mock_scanner = asynctest.CoroutineMock()
        mock_return = Mock()
        mock_scanner.return_value = mock_return
        mock_handler = asynctest.CoroutineMock()
        period = 2
        ending = asyncio.Future()

        loop.call_later(1, ending.set_result, True)
        loop.run_until_complete(script.scan_until_complete(loop, mock_scanner, mock_handler, period, ending))
        mock_handler.assert_called_with(mock_return)

        loop.close()
