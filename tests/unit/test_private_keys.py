import unittest

from dbt.exceptions import CompilationException

from dbt import flags

from dbt.adapters.snowflake import SnowflakeCredentials


class TestSnowflakeCredentials(unittest.TestCase):

    # a minimal test key generated using: openssl genrsa 32 | openssl pkcs8 -topk8 -inform PEM -out test_key.p8 -nocrypt
    TEST_KEY_BYTES=b'0C\x02\x01\x000\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x04/0-\x02\x01\x00\x02\x05\x00\xe4\xec\xaeq\x02\x03\x01\x00\x01\x02\x05\x00\xa0\xf5Y\xf5\x02\x03\x00\xfb\x1b\x02\x03\x00\xe9c\x02\x02,k\x02\x03\x00\x85\x99\x02\x028i'

    # as above, but omitting -nocrypt and setting the passphrase to `password`
    TEST_KEY_ENCRYPTED_BYTES=b'0C\x02\x01\x000\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x04/0-\x02\x01\x00\x02\x05\x00\xb4\x83`\xc5\x02\x03\x01\x00\x01\x02\x04o\x1c\xdf\x89\x02\x03\x00\xd9\xeb\x02\x03\x00\xd4\x0f\x02\x02G9\x02\x03\x00\x8d\x9f\x02\x03\x00\xb1\xad'

    def test_no_private_key(self):
        creds = SnowflakeCredentials(
            database="test",
            schema="test",
            account="test",
            user="test"
        )
        self.assertIsNone(creds.auth_args()["private_key"])

    def test_private_key_file(self):
        creds = SnowflakeCredentials(
            database="test",
            schema="test",
            account="test",
            user="test",
            private_key_path="test_key.p8"
        )
        self.assertEqual(self.TEST_KEY_BYTES, creds.auth_args()["private_key"])

    def test_private_key_encrypted_file(self):
        creds = SnowflakeCredentials(
            database="test",
            schema="test",
            account="test",
            user="test",
            private_key_path="test_key_encrypted.p8",
            private_key_passphrase="password"
        )
        self.assertEqual(self.TEST_KEY_ENCRYPTED_BYTES, creds.auth_args()["private_key"])

    def test_private_key_bytes(self):
        with open("test_key.p8", 'rb') as file:
            bytes_in = file.read()
        creds = SnowflakeCredentials(
            database="test",
            schema="test",
            account="test",
            user="test",
            private_key_bytes=bytes_in
        )
        self.assertEqual(self.TEST_KEY_BYTES, creds.auth_args()["private_key"])

    def test_private_key_bytes_encrypted(self):
        with open("test_key_encrypted.p8", 'rb') as file:
            bytes_in = file.read()
        creds = SnowflakeCredentials(
            database="test",
            schema="test",
            account="test",
            user="test",
            private_key_bytes=bytes_in,
            private_key_passphrase='password'
        )
        self.assertEqual(self.TEST_KEY_ENCRYPTED_BYTES, creds.auth_args()["private_key"])

    def test_cant_have_both_key_path_and_bytes(self):
        flags.WARN_ERROR = True
        with open("test_key.p8", 'rb') as file:
            bytes_in = file.read()
        creds = SnowflakeCredentials(
            database="test",
            schema="test",
            account="test",
            user="test",
            private_key_bytes=bytes_in,
            private_key_path="test_key.p8"
        )
        self.assertRaises(CompilationException)
        flags.WARN_ERROR = None
