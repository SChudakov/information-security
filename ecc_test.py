import unittest
from ecc import *


def _int_to_str(a: int) -> str:
    return bin(a)[2:]


class TestGF(unittest.TestCase):

    def test_to_f(self):
        powers = (257, 12, 0)
        expected_f = 0b100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000001
        self.assertEqual(expected_f, GF.to_f(powers))

    def test_add(self):
        a = 0b001010011
        b = 0b011001010
        self.assertEqual(0b010011001, GF.add(a, b))

    def test_multiply(self):
        a = 0b001010011
        b = 0b011001010
        f = 0b100011011
        self.assertEqual(1, GF.multiply(a, b, f))

    def test_square(self):
        a = 0b001010011
        f = 0b100011011
        self.assertEqual(0b10110101, GF.square(a, f))

    def test_divide(self):
        a = 0b001010011
        b = 0b011001010
        f = 0b100011011
        self.assertEqual(0b10110101, GF.divide(a, b, f))

    def test_modular_pow(self):
        a = 0b001010011
        f = 0b100011011
        pow = 2
        self.assertEqual(0b10110101, GF.modular_pow(a, pow, f))

    def test_sqrt(self):
        b = 0b011001010
        f = 0b100011011
        root = GF.sqrt(b, f)
        sq = GF.square(root, f)
        self.assertEqual(b, sq)

    def test_inverse(self):
        a = 0b001010011
        f = 0b100011011
        self.assertEqual(0b11001010, GF.inverse(a, f))

    def test_trace(self):
        m = 17
        f = 0b100000000000001001
        self.assertEqual(0, GF.trace(0b1101011000111000, m, f))
        self.assertEqual(0, GF.trace(0b10010001111101110, m, f))
        self.assertEqual(0, GF.trace(0b11111110111010100, m, f))
        self.assertEqual(1, GF.trace(0b1100001100000111, m, f))
        self.assertEqual(1, GF.trace(0b10110011010010101, m, f))
        self.assertEqual(1, GF.trace(0b110100111110101, m, f))
        self.assertEqual(1, GF.trace(0b11101010000000101, m, f))


class TestEllipticCurve(unittest.TestCase):
    _number_of_iterations = 10

    def test_point_on_curve(self):
        self._helper_point_on_curve(0b11001011101001100, 0b10110101001100011, 17,
                                    0b100000000000001001, (0b11011100010110000, 0b101001011110011), True)

    def _helper_point_on_curve(self, a, b, m, f, point, result):
        curve = EllipticCurve(a, b, m, f)
        self.assertEqual(result, curve.point_on_curve(point))

    def test_add_points(self):
        a, b, m, f = 0b11001011101001100, 0b10110101001100011, 17, 0b100000000000001001
        p1 = (0b11011100010110000, 0b101001011110011)
        p2 = (0b10101000111011011, 0b10111001010110001)
        expected_result = (0b10010010010001001, 0b11100011110011001)
        EC = EllipticCurve(a, b, m, f)
        self.assertEqual(expected_result, EC.add_points(p1, p2))

    def test_double_point(self):
        a, b, m, f = 0b11001011101001100, 0b10110101001100011, 17, 0b100000000000001001
        p1 = (0b11011100010110000, 0b101001011110011)
        expected_result = (0b11010011001010010, 0b110000000000011)
        EC = EllipticCurve(a, b, m, f)
        self.assertEqual(expected_result, EC.double_point(p1))

    def test_integer_multiple(self):
        a, b, m, f = 0b11001011101001100, 0b10110101001100011, 17, 0b100000000000001001
        p1 = (0b11011100010110000, 0b101001011110011)
        expected_result = (0b11111011100010100, 0b11111101001101010)
        EC = EllipticCurve(a, b, m, f)
        self.assertEqual(expected_result, EC.multiply_point(p1, 5))

    def test_random_field_element(self):
        a, b, m, f = 0b11001011101001100, 0b10110101001100011, 17, 0b100000000000001001
        curve = EllipticCurve(a, b, m, f)
        for i in range(TestEllipticCurve._number_of_iterations):
            field_element = curve._random_field_element()
            self.assertTrue(len(_int_to_str(field_element)) <= curve.m)

    def test_generate_point(self):
        print()
        a, b, m, f = 0b11001011101001100, 0b10110101001100011, 17, 0b100000000000001001
        curve = EllipticCurve(a, b, m, f)
        for i in range(TestEllipticCurve._number_of_iterations):
            random_point = curve.generate_point()
            print(f'generated_point: ({_int_to_str(random_point[0])},{_int_to_str(random_point[1])})')
            self.assertTrue(curve.point_on_curve(random_point))


class TestECC(unittest.TestCase):
    _curve163 = EllipticCurve(1,
                              0x5FF6108462A2DC8210AB403925E638A19C1455D21,
                              163,
                              powers_to_f((163, 7, 6, 3, 0)))
    _ecc163 = ECC(curve=_curve163, n=0x400000000000000000002BEC12BE2262D39BCF14D)
    _curve257 = EllipticCurve(0,
                              0x1CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10,
                              257,
                              powers_to_f((257, 12, 0)))
    _ecc257 = ECC(curve=_curve257, n=0x800000000000000000000000000000006759213AF182E987D3E17714907D470D)

    def test_signature(self):
        text = b'Hello, world!'
        signature = self._ecc257.sign(text)
        verified = self._ecc257.validate_signature(signature)
        self.assertTrue(verified)

    def test_transform_to_signature(self):
        r, s = 0b10100, 0b10011
        expected_signature = '0' * (256 - 5) + '10011' + '0' * (256 - 5) + '10100'
        self.assertEqual(expected_signature, self._ecc257._transform_to_signature(r, s))

    def test_transform_to_pair_of_numbers(self):
        signature = '0' * (256 - 5) + '10100' + '0' * (256 - 5) + '10011'
        expected_r, expected_s = 0b10011, 0b10100
        self.assertEqual((expected_r, expected_s), self._ecc257._transform_to_pair_of_numbers(signature))

    def test_base_point(self):
        self.assertTrue(self._ecc257._curve.point_on_curve(self._ecc257._P))

    def test_private_key(self):
        self.assertNotEqual(0, self._ecc257._d)
        self.assertTrue(self._ecc257._d.bit_length() < self._ecc257._n.bit_length())

    def test_calculate_public_key(self):
        self.assertTrue(self._ecc257._curve.point_on_curve(self._ecc257._Q))

    def test_calculate_pre_signature(self):
        self.assertTrue(self._ecc257._F_e.bit_length() <= self._ecc257._curve.m)
        self.assertTrue(self._ecc257._e.bit_length() < self._ecc257._n.bit_length())

    def test_calculate_random_integer(self):
        for _ in range(10):
            random_integer = self._ecc257._calculate_random_integer()
            self.assertTrue(random_integer.bit_length() < self._ecc257._n.bit_length())

    def test_to_number_bits(self):
        self.assertEqual('100101', self._ecc257._to_number_bits('0000100101'))
        self.assertEqual('1001111', self._ecc257._to_number_bits('0001001111'))


class E2ETestECC(unittest.TestCase):
    def test_e2e(self):
        print()
        A = 1
        B = 0x5FF6108462A2DC8210AB403925E638A19C1455D21
        m = 163
        f = powers_to_f((163, 7, 6, 3, 0))
        C = EllipticCurve(A, B, 163, f)

        n = 0x400000000000000000002BEC12BE2262D39BCF14D
        P = (0x72D867F93A93AC27DF9FF01AFFE74885C8C540420, 0x0224A9C3947852B97C5599D5F4AB81122ADC3FD9B)
        d = 0x183F60FDF7951FF47D67193F8D073790C1C9B5A3E
        Q = (0x057DE7FDE023FF929CB6AC785CE4B79CF64ABDC2DA, 0x3E85444324BCF06AD85ABF6AD7B5F34770532B9AA)

        nP = C.multiply_point(P, n)
        minus_dP = C.negate_point(C.multiply_point(P, d))
        print(f'Q: ({hex(Q[0])},{hex(Q[1])})')
        print(f'-(dP): ({hex(minus_dP[0])},{hex(minus_dP[1])})')
        self.assertEqual(C.zero, nP)
        self.assertEqual(Q, minus_dP)

        ecc = ECC(C, n, P)

        hash = b'\x09\xC9\xC4\x42\x77\x91\x0C\x9A\xAE\xE4\x86\x88\x3A\x2E\xB9\x5B\x71\x80\x16\x6D\xDF\x73\x53\x2E\xEB\x76\xED\xAE\xF5\x22\x47\xFF'
        h = ecc._transform_to_field_element(hash)
        e = 0x1025E40BD97DB012B7A1D79DE8E12932D247F61C6
        F_e_point = (0x42A7D756D70E1C9BA62D2CB43707C35204EF3C67C, 0x5310AE5E560464A95DC80286F17EB762EC544B15B)
        F_e = 0x42A7D756D70E1C9BA62D2CB43707C35204EF3C67C
        eP = C.multiply_point(P, e)
        print(f'hash_field_element : {hex(h)}')
        self.assertEqual(0x03A2EB95B7180166DDF73532EEB76EDAEF52247FF, h)
        print(f'F_e_point : ({hex(F_e_point[0])},{hex(F_e_point[1])})')
        print(f'eP : ({hex(eP[0])},{hex(eP[1])})')
        self.assertEqual(F_e_point, eP)
        y = GF.multiply(h, F_e, f)
        r = ecc._transform_to_integer(y)
        s = (e + d * r) % n
        self.assertEqual(0x274EA2C0CAA014A0D80A424F59ADE7A93068D08A7, y)
        self.assertEqual(0x274EA2C0CAA014A0D80A424F59ADE7A93068D08A7, r)
        self.assertEqual(0x2100D86957331832B8E8C230F5BD6A332B3615ACA, s)
        self.assertEqual((r, s), ecc._transform_to_pair_of_numbers(ecc._transform_to_signature(r, s)))
        R = (0x42A7D756D70E1C9BA62D2CB43707C35204EF3C67C, 0x5310AE5E560464A95DC80286F17EB762EC544B15B)
        sP_plus_rQ = C.add_points(
            C.multiply_point(P, s),
            C.multiply_point(Q, r)
        )
        print(f'R          = ({hex(R[0])},{hex(R[1])})')
        print(f'sP_plus_rQ = ({hex(sP_plus_rQ[0])},{hex(sP_plus_rQ[1])})')
        self.assertEqual(R, sP_plus_rQ)


if __name__ == '__main__':
    unittest.main()
