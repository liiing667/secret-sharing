# -*- coding: utf-8 -*-
"""
    Secret Sharing
    ~~~~~

    :copyright: (c) 2014 by Halfmoon Labs
    :license: MIT, see LICENSE for more details.
"""

import random
import unittest
from test import test_support
from utilitybelt import base64_chars
from secretsharing import secret_int_to_points, points_to_secret_int, \
    point_to_share_string, share_string_to_point, SecretSharer, \
    HexToHexSecretSharer, PlaintextToHexSecretSharer, \
    BitcoinToB58SecretSharer, BitcoinToB32SecretSharer, \
    BitcoinToZB32SecretSharer
from secretsharing.primes import get_large_enough_prime


class ShamirSharingTest(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def split_and_recover_secret(self, sharer_class, m, n, secret):
        shares = sharer_class.split_secret(secret, m, n)
        random.shuffle(shares)
        recovered_secret = sharer_class.recover_secret(shares[0:m])
        assert(recovered_secret == secret)

    def test_hex_to_hex_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            SecretSharer, 3, 5,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_printable_ascii_to_hex_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            PlaintextToHexSecretSharer, 3, 5,
            "correct horse battery staple")

    def test_b58_to_b32_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            BitcoinToB32SecretSharer, 3, 5,
            "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS")

    def test_b58_to_zb32_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            BitcoinToZB32SecretSharer, 3, 5,
            "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS")

    def test_b58_to_b58_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            BitcoinToB58SecretSharer, 3, 5,
            "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS")

    def test_hex_to_base64_sharing(self):
        class Base64SecretSharer(SecretSharer):
            share_charset = base64_chars
        sharer_class = Base64SecretSharer
        recovered_secret = self.split_and_recover_secret(
            sharer_class, 3, 5,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_2_of_3_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            SecretSharer, 2, 3,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_4_of_7_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            SecretSharer, 4, 7,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_5_of_9_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            SecretSharer, 5, 9,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_2_of_2_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            SecretSharer, 2, 2,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_share_string_to_point_round_trip(self):
        point = (1, 4938573982723)
        share_string = point_to_share_string(
            point, HexToHexSecretSharer.share_charset)
        self.assertEqual(
            share_string_to_point(
                share_string, HexToHexSecretSharer.share_charset),
            point)

    def test_malformed_share_strings_are_rejected(self):
        charset = HexToHexSecretSharer.share_charset
        malformed_shares = [
            None,
            12345,
            '1-',
            '-abc',
            '1-2-3',
            'nohyphen',
            '1-zzz',
            '',
        ]
        for malformed_share in malformed_shares:
            with self.assertRaises(ValueError):
                share_string_to_point(malformed_share, charset)

    def test_recover_secret_rejects_malformed_shares(self):
        shares = SecretSharer.split_secret(
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a",
            3, 5)
        for malformed_share in ['1-', '-abc', '1-2-3', 'nohyphen',
                                '1-zzz', None, 12345]:
            bad_shares = [malformed_share] + shares[1:3]
            with self.assertRaises(ValueError):
                SecretSharer.recover_secret(bad_shares)

    def test_recover_secret_rejects_duplicate_x(self):
        shares = SecretSharer.split_secret(
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a",
            3, 5)
        with self.assertRaises(ValueError):
            SecretSharer.recover_secret([shares[0], shares[0], shares[1]])
        with self.assertRaises(ValueError):
            points_to_secret_int([(1, 10), (1, 20), (2, 30)])

    def test_recover_secret_rejects_zero_x(self):
        shares = SecretSharer.split_secret(
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a",
            3, 5)
        with self.assertRaises(ValueError):
            SecretSharer.recover_secret(
                ['0-deadbeef', shares[1], shares[2]])
        with self.assertRaises(ValueError):
            points_to_secret_int([(0, 10), (1, 20), (2, 30)])

    def test_points_to_secret_int_rejects_out_of_range_points(self):
        prime = get_large_enough_prime([0])
        with self.assertRaises(ValueError):
            points_to_secret_int([(prime, 1), (1, 2)])
        with self.assertRaises(ValueError):
            points_to_secret_int([(1, prime), (2, 1)])
        with self.assertRaises(ValueError):
            points_to_secret_int([(1, -1), (2, 1)])

    def test_points_to_secret_int_rejects_malformed_points(self):
        for malformed_points in [
            [(1, 2), [3, 4]],
            [(1, 2), (3,)],
            [(1, 2), (3, '4')],
        ]:
            with self.assertRaises(ValueError):
                points_to_secret_int(malformed_points)

    def test_legacy_share_format_still_recovers(self):
        legacy_shares = [
            '1-58cbd30524507e7a198bdfeb69c8d87fd7d2c10e8d5408851404f7d258cbcea7',
            '2-ecdbdaea89d75f8e73bde77a46db821cd40f430d39a11c864e5a4868dcb403ed',
        ]
        self.assertEqual(
            SecretSharer.recover_secret(legacy_shares),
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_any_threshold_combination_still_recovers(self):
        secret = "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a"
        for m, n in [(2, 3), (3, 5), (4, 7), (5, 9)]:
            shares = SecretSharer.split_secret(secret, m, n)
            random.shuffle(shares)
            self.assertEqual(
                SecretSharer.recover_secret(shares[:m]), secret)


def test_main():
    test_support.run_unittest(
        ShamirSharingTest
    )


if __name__ == '__main__':
    test_main()
