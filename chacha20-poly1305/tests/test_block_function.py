from unittest import TestCase

from block_function import reverse_blocks_of_4, int_to_words, state_builder, block_function, twenty_rounds, serialize, next_state


class BlockFunctionTest(TestCase):

    def test_reverse_blocks_of_4(self):

        self.assertEqual(50462976, reverse_blocks_of_4(0x00010203))    # --> 0x3020100
        self.assertEqual(522067228, reverse_blocks_of_4(0x1C1D1E1F))  # --> 0x1f1e1d1c


    def test_int_to_words(self):

        key_256 = 0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
        # 0x 00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617 18191A1B 1C1D1E1F
        expected = [0x3020100, 0x7060504, 0x0b0a0908, 0x0F0E0D0C, 0x13121110, 0x17161514, 0x1B1A1918, 0x1f1e1d1c]
        # [50462976, 117835012, 185207048, 252579084, 319951120, 387323156, 454695192, 522067228]
        words = int_to_words(key_256, 256)
        self.assertEqual(expected, words)


    def test_state_builder(self): # Exemple tiré du RFC 8439 (section 2.3.2)

        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        nonce = 0x000000090000004a00000000
        counter = 1

        expected_state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,   # Constantes
                          0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,   # Key
                          0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,   # Key
                          0x00000001, 0x09000000, 0x4a000000, 0x00000000]   # Counter + Nonce

        self.assertEqual(expected_state, state_builder(key, counter, nonce))


    def test_twenty_rounds(self):

        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        nonce = 0x000000090000004a00000000
        counter = 1

        expected_state = [0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f,
                          0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7,
                          0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd,
                          0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2]

        self.assertEqual(expected_state, twenty_rounds(state_builder(key, counter, nonce)))


    def test_block_function(self):

        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        nonce = 0x000000090000004a00000000
        counter = 1

        expected_state = [0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
                          0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
                          0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
                          0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2]

        self.assertEqual(expected_state, block_function(state_builder(key, counter, nonce)))


    def test_serialize(self):

        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        nonce = 0x000000090000004a00000000
        counter = 1

        expected = 0x10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e

        block = serialize(block_function(state_builder(key, counter, nonce)))
        self.assertEqual(expected, block)


    def test_next_state(self):
        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        nonce = 0x000000090000004a00000000
        counter = 1

        expected_state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                          0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                          0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                          0x00000002, 0x09000000, 0x4a000000, 0x00000000]

        self.assertEqual(expected_state, next_state(state_builder(key, counter, nonce)))