from unittest import TestCase

from chacha20 import chacha20_encrypt


class ChaCha20EncryptTest(TestCase):

    def test_chacha20_encrypt(self):  # Exemple tiré du RFC 8439 (section 2.4.2)  ->  len(hex_str) = 64 + 50

        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        nonce = 0x000000000000004a00000000
        counter = 1
        hex_str = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
        # text = bytes.fromhex(hex_str).decode("utf-8")
        # print(text)
        # print(bytes.fromhex(hex_str))

        cypher = chacha20_encrypt(key, counter, nonce, bytes.fromhex(hex_str))
        # print(cypher.hex())
        expected = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
        self.assertEqual(len(cypher.hex()), len(hex_str))
        self.assertEqual(expected, cypher.hex())


    def test_chacha20_decrypt(self):
        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        nonce = 0x000000000000004a00000000
        counter = 1
        hex_str = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"

        cypher = chacha20_encrypt(key, counter, nonce, bytes.fromhex(hex_str))
        expected = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
        self.assertEqual(len(cypher.hex()), len(hex_str))
        self.assertEqual(expected, cypher.hex())


    def test_chacha20_encrypt_plaintext_court(self):

        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        nonce = 0x000000000000004a00000000
        counter = 1
        plaintext = b"L'adversaire observe tout"
        ciphertext = chacha20_encrypt(key, counter, nonce, plaintext)
        expected = "6e683097367eab924eb7550a980c7f9ee96169e71d5869970a"

        self.assertEqual(len(ciphertext), len(plaintext))
        self.assertEqual(expected, ciphertext.hex())
        self.assertEqual(plaintext, chacha20_encrypt(key, counter, nonce, bytes.fromhex(expected)))
