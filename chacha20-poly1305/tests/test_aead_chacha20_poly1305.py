from unittest import TestCase


from aead_chacha20_poly1305 import aead_chacha20_poly1305_encrypt, aead_chacha20_poly1305_decrypt


class AeadChacha20Poly1305EncryptTest(TestCase):


    def test_aead_chacha20_poly1305_encrypt(self):

        key = 0x808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
        nonce = 0x070000004041424344454647
        plaintext = ("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496620492063"
                     "6f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
                     "637265656e20776f756c642062652069742e")
        # text = bytes.fromhex(plaintext).decode("utf-8")
        # print("plaintext : ", text)
        aad = "50515253c0c1c2c3c4c5c6c7"

        expected_cipher_hex = ("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca96712"
                               "82fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58"
                               "fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116")

        expected_tag_hex = "1ae10b594f09e26a7e902ecbd0600691"

        ciphertext, tag = aead_chacha20_poly1305_encrypt(key, nonce, bytes.fromhex(plaintext), bytes.fromhex(aad))

        self.assertEqual(len(plaintext), len(ciphertext.hex()))
        self.assertEqual(expected_cipher_hex, ciphertext.hex())
        self.assertEqual(16, len(tag))
        self.assertEqual(expected_tag_hex, tag.hex())


    def test_aead_chacha20_poly1305_encrypt_2(self):

        key = 0
        nonce = int.from_bytes(b'1' * 24)
        plaintext = b"hello"
        aad =  b"aad"

        expected_cipher_hex = "4aec3ae5c5"
        expected_tag_hex = "79662fc4f3cf1a2b50a03e0b8aafba36"

        ciphertext, tag = aead_chacha20_poly1305_encrypt(key, nonce, plaintext, aad)

        self.assertEqual(5, len(ciphertext))
        self.assertEqual(expected_cipher_hex, ciphertext.hex())
        self.assertEqual(16, len(tag))
        self.assertEqual(expected_tag_hex, tag.hex())


class AeadChacha20Poly1305DecryptTest(TestCase):

    def test_aead_chacha20_poly1305_decrypt(self):

        key = 0x808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
        nonce = 0x070000004041424344454647

        ciphertext = ("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca96712"
                      "82fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58"
                      "fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116")

        aad = "50515253c0c1c2c3c4c5c6c7"

        plaintext, tag = aead_chacha20_poly1305_decrypt(key, nonce, bytes.fromhex(ciphertext), bytes.fromhex(aad))

        expected_plaintext_hex = ("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a"
                                   "204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f72207468"
                                   "65206675747572652c2073756e73637265656e20776f756c642062652069742e")
        expected_tag_hex = "1ae10b594f09e26a7e902ecbd0600691"

        self.assertEqual(len(ciphertext), len(plaintext.hex()))
        self.assertEqual(expected_plaintext_hex, plaintext.hex())
        self.assertEqual(16, len(tag))
        self.assertEqual(expected_tag_hex, tag.hex())
        # text = plaintext.decode("utf-8")
        # print("plaintext :", text)


    def test_aead_chacha20_poly1305_decrypt_2(self):

        key = 0
        nonce = int.from_bytes(b'1' * 24)
        msg = b"secret"
        aad = b"hdr"

        ciphertext, tag1 = aead_chacha20_poly1305_encrypt(key, nonce, msg, aad)
        plaintext, tag2 = aead_chacha20_poly1305_decrypt(key, nonce, ciphertext, aad)


        self.assertEqual(len(ciphertext), len(plaintext))
        self.assertEqual(16, len(tag1))
        self.assertEqual(16, len(tag2))
        self.assertEqual(tag1, tag2)
        # text = plaintext.decode("utf-8")
        # print("plaintext :", text)
