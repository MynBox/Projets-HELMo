from unittest import TestCase

from poly1305 import le_bytes_to_int, clamp_r, poly1305_mac, poly1305_key_gen_chacha20, int_to_le_bytes


class ConversionsTest(TestCase):

    def test_le_bytes_to_int_base(self):

        self.assertEqual(0, le_bytes_to_int(b"\x00"))
        self.assertEqual(1, le_bytes_to_int(b"\x01"))
        self.assertEqual(1, le_bytes_to_int(b"\x01\x00"))
        self.assertEqual(16, le_bytes_to_int(b"\x10\x00"))

        self.assertEqual(0, le_bytes_to_int(b""))
        self.assertEqual(255, le_bytes_to_int(b"\xFF"))

        self.assertEqual(0xFFFFFFFF, le_bytes_to_int(b"\xFF\xFF\xFF\xFF"))
        self.assertEqual(1, le_bytes_to_int(b"\x01\x00\x00\x00\x00"))

        self.assertEqual(0x1234, le_bytes_to_int(b"\x34\x12\x00"))
        self.assertEqual(0xA1B2C3D4, le_bytes_to_int(b"\xD4\xC3\xB2\xA1"))


    def test_le_bytes_to_int(self):
        s = bytes.fromhex("0103808afb0db2fd4abff6af4149f51b")
        s_int = le_bytes_to_int(s)
        self.assertEqual(int, type(s_int))
        self.assertEqual(0x1bf54941aff6bf4afdb20dfb8a800301, s_int)


    def test_int_to_le_bytes_base(self):

        self.assertEqual(b"\x01", int_to_le_bytes(1, 1))
        self.assertEqual(b"\x01\x00", int_to_le_bytes(1, 2))
        self.assertEqual(b"\x02\x01", int_to_le_bytes(258, 2))

        self.assertEqual(b"\x00", int_to_le_bytes(0, 1))
        self.assertEqual(b"\x00\x00\x00\x00", int_to_le_bytes(0, 4))

        self.assertEqual(b"", int_to_le_bytes(1234, 0))
        self.assertEqual(b"\xFF", int_to_le_bytes(0xFF, 1))
        self.assertEqual(b"\xFF\xFF", int_to_le_bytes(0xFFFF, 2))
        self.assertEqual(b"\xFF\xFF\xFF\xFF", int_to_le_bytes(0xFFFFFFFF, 4))

        self.assertEqual(b"\x56\x34", int_to_le_bytes(0x123456, 2))
        self.assertEqual(b"\x34\x12\xEF", int_to_le_bytes(0xABCDEF1234, 3))
        self.assertEqual(b"\xD4\xC3\xB2\xA1", int_to_le_bytes(0xA1B2C3D4, 4))

    def test_int_to_le_bytes(self):
        s_int = 0x1bf54941aff6bf4afdb20dfb8a800301
        s_bytes = int_to_le_bytes(s_int, 16)
        self.assertEqual(bytes, type(s_bytes))
        self.assertEqual(bytes.fromhex("0103808afb0db2fd4abff6af4149f51b"), s_bytes)


class Poly1305Test(TestCase):

    # Tests basés sur l'exemple présenté dans le RFC 8439 (section 2.5.2)

    def test_r_clamping_from_r(self):
        r = bytes.fromhex("85d6be7857556d337f4452fe42d506a8")
        r_clamped = clamp_r(r)
        self.assertEqual(int, type(r_clamped))
        self.assertEqual(0x806d5400e52447c036d555408bed685,r_clamped)

    def test_r_clamping_from_key(self):
        key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        r = key[:16]
        r_clamped = clamp_r(r)
        self.assertEqual(int, type(r_clamped))
        self.assertEqual(0x806d5400e52447c036d555408bed685,r_clamped)


    def test_poly1305_mac(self):

        key_hex = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
        msg = b"Cryptographic Forum Research Group"
        msg_hex = "43727970746f6772617068696320466f72756d2052657365617263682047726f7570"
        expected_tag_hex = "a8061dc1305136c6c22b8baf0c0127a9"

        key = bytes.fromhex(key_hex)
        self.assertEqual(0x85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b.to_bytes(length=32), key)

        tag = poly1305_mac(msg, key)
        self.assertEqual(bytes, type(tag))
        self.assertEqual(tag.hex(), expected_tag_hex)

        tag = poly1305_mac(bytes.fromhex(msg_hex), key)
        self.assertEqual(bytes, type(tag))
        self.assertEqual(tag.hex(), expected_tag_hex)


    # Test basé sur l'exemple présenté dans le RFC 8439 (section 2.6.2)

    def test_poly1305_key_gen_chacha20(self):

        key = 0x808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f        # (256 bits)
        nonce = 0x000000000001020304050607                                              # (96 bits)
        expected = "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646"
        key_gen = poly1305_key_gen_chacha20(key, nonce)
        self.assertEqual(bytes, type(key_gen))
        self.assertEqual(bytes.fromhex(expected), key_gen)


    def test_poly1305_key_gen_section_2_6_2(self):
        """
        RFC 7539 §2.6 (p.17-18) : poly1305_key_gen(key, nonce) = chacha20_block(key,0,nonce)[0..31]
        On valide contre le keystream ChaCha20 bien connu (Appendix A.1/#1 ; cohérent avec §2.6).
        key = 32*0x00, nonce = 12*0x00 -> one-time key =
        76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28
        bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
        """
        key = 0x00
        nonce = 0x00
        expected = "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"

        key_gen = poly1305_key_gen_chacha20(key, nonce)
        self.assertEqual(bytes, type(key_gen))
        self.assertEqual(bytes.fromhex(expected), key_gen)
