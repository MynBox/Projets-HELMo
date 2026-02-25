from unittest import TestCase

from quarter_round import sum_mod_232, circular_shift_left, quarter_round, quarter_round_on_selected


class SumMod232Test(TestCase):

    def test_sum_no_mod(self):
        a = 2 ** 32 // 2
        b = a - 5
        self.assertEqual(2 ** 32 - 5, sum_mod_232(a, b))

    def test_sum_mod(self):
        a = 2 ** 32 // 2
        b = a + 1
        self.assertEqual(1, sum_mod_232(a, b))

    # Ajout test MC
    # 3,185,679,456 + 1,825,356,879 = 5,011,036,335   -> 716,069,039
    def test_sum_mod_2(self):
        a = 3185679456
        b = 1825356879
        self.assertEqual(5011036335, a + b)
        self.assertEqual(716069039, sum_mod_232(a, b))


class CircularShiftLeftTest(TestCase):

    def test_circular_shift_left_4bits_1bit(self):
        self.assertEqual(0b0101, circular_shift_left(0b1010, 4, 1))
        self.assertEqual(0b1010, circular_shift_left(0b0101, 4, 1))

    def test_circular_shift_left_7bits_1bit(self):
        self.assertEqual(0b0101111, circular_shift_left(0b1010111, 7, 1))
        self.assertEqual(0b1011110, circular_shift_left(0b0101111, 7, 1))

    def test_circular_shift_left_7bits_3bits(self):
        self.assertEqual(0b0111101, circular_shift_left(0b1010111, 7, 3))

    def test_circular_shift_left_32bits_1bit(self):
        self.assertEqual(0x3, circular_shift_left(0x80000001, 32, 1))

    def test_circular_shift_left_32bits_2bits(self):
        self.assertEqual(0x6, circular_shift_left(0x80000001, 32, 2))

    def test_circular_shift_left_32bits_12bits(self):
        self.assertEqual(0x45678123, circular_shift_left(0x12345678, 32, 12))

    def test_circular_shift_left__32bits_20bits(self):
        self.assertEqual(0x67812345, circular_shift_left(0x12345678, 32, 20))


class QuarterRoundTest(TestCase):

    def test_quarter_round_simple(self):
        self.assertEqual((0x10000001, 0x80808808, 0x01010110, 0x01000110), quarter_round(1, 0, 0, 0))

    def test_quarter_round(self):  # Exemple tiré du RFC 8439 (section 2.1.1)
        self.assertEqual((0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb),
                         quarter_round(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567))

    def test_quarter_round_2(self):
        self.assertEqual((0x8000c004, 0x64624444, 0x08c80488, 0x08c00480), quarter_round(0, 4, 8, 12))


class QuarterRoundOnSelectedTest(TestCase):

    def test_quarter_round_on_selected(self): # Exemple tiré du RFC 8439 (section 2.1.1)

        state_i = [0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
                   0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
                   0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
                   0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320]

        state_o = [0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
                   0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
                   0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
                   0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320]

        result = quarter_round_on_selected(state_i, [2, 7, 8, 13]) # "diagonal round"
        self.assertEqual(state_o, result)

    def test_quarter_round_on_selected_2(self):

        state_i = list(range(16))
        state_o = [0x8000c004, 1, 2, 3,
                   0x64624444, 5, 6, 7,
                   0x08c80488, 9, 10, 11,
                   0x08c00480, 13, 14, 15]
        result = quarter_round_on_selected(state_i, [0, 4, 8, 12]) # first column
        self.assertEqual(state_o, result)

    def test_quarter_round_on_selected_3(self):

        state_i = [i for i in range(16)]
        state_o = [0xa000f005, 1, 2, 3,
                   4, 0x7d7ad555, 6, 7,
                   8, 9, 0xafa05aa, 11,
                   12, 13, 14, 0xaf005a0]
        result = quarter_round_on_selected(state_i, [0, 5, 10, 15]) # main diagonal
        self.assertEqual(state_o, result)
