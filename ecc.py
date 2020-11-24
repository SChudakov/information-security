import os
import sys
import math
import sha256
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler(sys.stdout))


def _int_to_str(a: int) -> str:
    return bin(a)[2:]


def _str_to_int(a: str) -> int:
    return int(a, 2)


def powers_to_f(powers):
    result = 0
    for power in powers:
        result += 1 << power
    return result


def _reversed_string(s: str):
    return s[::-1]


class GF:
    @staticmethod
    def to_f(powers):
        result = 0
        for power in powers:
            result += 1 << power
        return result

    @staticmethod
    def _m(f: int):
        return f.bit_length() - 1

    @staticmethod
    def add(a: int, b: int):
        return a ^ b

    @staticmethod
    def multiply(a: int, b: int, f: int):
        m = GF._m(f)
        assert a.bit_length() <= m
        assert b.bit_length() <= m

        mask = (1 << m) - 1
        p = 0
        while a > 0 and b > 0:
            if b & 1:
                p ^= a
            if a & (1 << (m - 1)):
                a = ((a << 1) ^ f) & mask
            else:
                a <<= 1
                a &= mask
            b >>= 1
        return p

    @staticmethod
    def divide(a: int, b: int, f: int):
        return GF.multiply(a, GF.inverse(b, f), f)

    @staticmethod
    def modular_pow(a: int, pow: int, f: int):
        str_pow = _int_to_str(pow)
        multiplier = a
        result = 1
        for i in range(len(str_pow) - 1, -1, -1):
            if str_pow[i] == '1':
                result = GF.multiply(result, multiplier, f)
            multiplier = GF.square(multiplier, f)
        return result

    @staticmethod
    def square(a, f):
        return GF.multiply(a, a, f)

    @staticmethod
    def sqrt(a, f):
        m = GF._m(f)
        return GF.modular_pow(a, 2 ** (m - 1), f)

    @staticmethod
    def inverse(a: int, f: int):
        m = GF._m(f)
        return GF.modular_pow(a, 2 ** m - 2, f)

    @staticmethod
    def trace(x, m, f):
        t = x
        for i in range(1, m):
            t = GF.add(GF.modular_pow(t, 2, f), x)
        assert t in {0, 1}
        return t

    @staticmethod
    def half_trace(x, m, f):
        assert (m & 1) > 0
        t = x
        for i in range(1, ((m - 1) // 2) + 1):
            t = GF.add(GF.modular_pow(t, 4, f), x)
        return t


class EllipticCurve:
    def __init__(self, A, B, m, f):
        assert A.bit_length() <= m
        assert B.bit_length() <= m
        assert f.bit_length() == m + 1
        self.A = A
        self.B = B
        self.m = m
        self.f = f
        self.zero = (0, 0)
        self.mask = (1 << self.m) - 1

    # def add_points(self, p1, p2):
    #     x = 0
    #     y = 0
    #     return x, y
    #
    # def double_point(self, P):
    #     pass

    def add_points(self, p1, q1):
        if p1 == self.zero:
            return q1
        if q1 == self.zero:
            return p1
        if p1[0] == q1[0] and p1[1] != q1[1]:  # p1 + -p1 == 0
            return self.zero
        if p1[0] == q1[0]:  # p1 == p2
            return self.double_point(p1)
        else:
            Lambda = GF.divide(GF.add(p1[1], q1[1]), GF.add(p1[0], q1[0]), self.f)
            x = GF.add(GF.add(GF.add(GF.add(GF.square(Lambda, self.f), Lambda), p1[0]), q1[0]), self.A)
            y = GF.add(GF.add(GF.multiply(GF.add(p1[0], x), Lambda, self.f), x), p1[1])
            return x, y

    def double_point(self, P):
        if P == self.negate_point(P):
            return self.zero
        else:
            Lambda = GF.add(P[0], GF.divide(P[1], P[0], self.f))
            x = GF.add(GF.add(GF.square(Lambda, self.f), Lambda), self.A)
            y = GF.add(GF.add(GF.square(P[0], self.f), GF.multiply(Lambda, x, self.f)), x)
            return x, y

    @staticmethod
    def negate_point(point):
        x, y = point
        return x, x ^ y

    def multiply_point(self, point, d: int):
        result = (0, 0)
        addend = point
        while d > 0:
            if d % 2 == 1:
                result = self.add_points(result, addend)
            addend = self.double_point(addend)
            d //= 2
        return result

    def point_on_curve(self, point):
        x, y = point
        assert x.bit_length() <= self.m
        assert y.bit_length() <= self.m
        return GF.add(GF.modular_pow(y, 2, self.f), GF.multiply(x, y, self.f)) == (
            GF.add(
                GF.add(GF.modular_pow(x, 3, self.f), GF.multiply(self.A, GF.modular_pow(x, 2, self.f), self.f)),
                self.B)
        )

    def generate_point(self):
        while True:
            u = self._random_field_element()
            w = GF.add(
                GF.add(
                    GF.modular_pow(u, 3, self.f),
                    GF.multiply(self.A, GF.square(u, self.f), self.f)
                ),
                self.B
            )
            solution = self._solve_quadratic_equation((u, w))
            if solution[1] == 2:
                return u, solution[0]

    def _random_field_element(self):
        length = math.ceil(self.m / 8)
        R = os.urandom(length)
        return int.from_bytes(R, 'big') & self.mask

    def _solve_quadratic_equation(self, params):
        u, w = params

        if u == 0:
            return GF.sqrt(w, self.f), 2
        elif w == 0:
            return 0, 2

        u_square = GF.square(u, self.f)
        v = GF.divide(w, u_square, self.f)

        v_trace = GF.trace(v, self.m, self.f)
        if v_trace == 1:
            return 0, 0

        t = GF.half_trace(v, self.m, self.f)
        z = GF.multiply(t, u, self.f)
        return z, 2


class ECC:
    _default_A = 1
    _default_B = 0x1CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10
    _default_m = 257
    _default_f = GF.to_f((257, 12, 0))
    assert _default_f.bit_length() == _default_m + 1
    _default_n = 0x800000000000000000000000000000006759213AF182E987D3E17714907D470D
    _default_curve = EllipticCurve(
        _default_A,
        _default_B,
        _default_m,
        _default_f
    )

    def __init__(self, curve=_default_curve, n=_default_n, P=None):
        self._curve = curve
        self._n = n  # order of base point
        self._L_n = self._n.bit_length()
        if P is None:
            self._P = self._calculate_base_point()  # base point
        else:
            self._P = P
        self._d = self._calculate_private_key()  # private key
        self._Q = self._calculate_public_key()  # public key
        self._e, self._F_e = self._calculate_pre_signature()  # e and pre-signature
        self._L_h = 256
        self._H = sha256.SHA256()
        self._iH = 'SHA-256'
        self._L_D = math.ceil((2 * self._L_n) / 16) * 16

    def sign(self, T: bytes):
        T_hash = self._H.hash(T)
        h = self._transform_to_field_element(T_hash)
        if h == 0:
            h = 1
        y = GF.multiply(self._F_e, h, self._curve.f)
        r = self._transform_to_integer(y)
        if r == 0:
            raise Exception(f'invalid r: {r}')
        s = (self._e + self._d * r) % self._n
        if s == 0:
            raise Exception(f'invalid s: {s}')
        D = self._transform_to_signature(r, s)
        logger.info(f'Signing = {T}')
        logger.info(f'T_hash = {T_hash}')
        logger.info(f'h = {h}')
        logger.info(f'y = {y}')
        logger.info(f'r = {r}')
        logger.info(f's = {s}')
        logger.info(f'D = {D}')
        return self._iH, T, D

    def validate_signature(self, signature: str):
        iH, T, D = signature
        if not iH == self._iH:
            raise Exception(f'unsupported hash function id {iH}')
        T_hash = self._H.hash(T)
        h = self._transform_to_field_element(T_hash)
        if h == 0:
            h = 1
        r, s = self._transform_to_pair_of_numbers(D)
        if not (0 < r.bit_length() < self._L_n):
            return False
        if not (0 < s.bit_length() < self._L_n):
            return False
        R = self._curve.add_points(
            self._curve.multiply_point(self._P, s),
            self._curve.multiply_point(self._Q, r)
        )
        y = GF.multiply(h, R[0], self._curve.f)
        r_prime = self._transform_to_integer(y)
        logger.info(f'Verifying signature for {T}')
        logger.info(f'D = {D}')
        logger.info(f'T_hash = {T_hash}')
        logger.info(f'h = {h}')
        logger.info(f'r = {r}')
        logger.info(f's = {s}')
        logger.info(f'R = {R}')
        logger.info(f'y = {y}')
        logger.info(f'r_prime = {r_prime}')
        return r == r_prime

    def _transform_to_field_element(self, hash: bytes):
        return int.from_bytes(hash, 'big') & self._curve.mask

    def _transform_to_integer(self, element):
        if element == 0:
            return 1
        mask = (1 << (self._L_n - 1)) - 1
        return element & mask

    def _transform_to_signature(self, r, s):
        l = self._L_D // 2
        l_r = r.bit_length()
        l_s = s.bit_length()
        R = '0' * (l - l_r) + _int_to_str(r)
        S = '0' * (l - l_s) + _int_to_str(s)
        return S + R

    def _transform_to_pair_of_numbers(self, D):
        l = self._L_D // 2
        S = D[:l]
        R = D[l:]
        s_bits = ECC._to_number_bits(S)
        r_bits = ECC._to_number_bits(R)
        return _str_to_int(r_bits), _str_to_int(s_bits)

    def _calculate_base_point(self):
        logger.info('Calculating base point...')
        i = 0
        while True:
            logger.info(f'attempt: {i}')
            i = i + 1
            candidate = self._curve.generate_point()
            logger.info(f'candidate: {candidate}')
            multiplied = self._curve.multiply_point(candidate, self._n)
            logger.info(f'multiplied: {multiplied}')
            if multiplied == self._curve.zero:
                logger.info(f'P = {candidate}')
                return candidate

    def _calculate_private_key(self):
        logger.info('Calculating private key...')
        while True:
            candidate = self._calculate_random_integer()
            if not candidate == 0:
                logger.info(f'd = {candidate}')
                return candidate

    def _calculate_public_key(self):
        result = self._curve.negate_point(
            self._curve.multiply_point(self._P, self._d)
        )
        logger.info(f'Q = {result}')
        return result

    def _calculate_pre_signature(self):
        logger.info('Calculating pre-signature...')
        while True:
            e = self._calculate_random_integer()
            candidate = self._curve.multiply_point(self._P, e)
            if not candidate[0] == 0:
                logger.info(f'e = {e}')
                logger.info(f'F_e = {candidate[0]}')
                logger.info(f'F_e point = {candidate}')
                return e, candidate[0]

    def _calculate_random_integer(self):
        length = math.ceil((self._L_n - 1) / 8)
        R = os.urandom(length)
        mask = (1 << (self._L_n - 1)) - 1
        return int.from_bytes(R, 'big') & mask

    @staticmethod
    def _to_number_bits(s: str):
        first_one_index = s.find('1')
        return s[first_one_index:]


def run(ecc):
    text = b'Hello, world!'
    signature = ecc.sign(text)
    verified = ecc.validate_signature(signature)
    print(f'verified: {verified}')


if __name__ == '__main__':
    curve163 = EllipticCurve(1,
                             0x5FF6108462A2DC8210AB403925E638A19C1455D21,
                             163,
                             powers_to_f((163, 7, 6, 3, 0)))
    print('\nInitializing ECC 163\n')
    ecc163 = ECC(curve=curve163, n=0x400000000000000000002BEC12BE2262D39BCF14D)
    print('\nRunning ECC 163\n')
    run(ecc163)
    curve257 = EllipticCurve(0,
                             0x1CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10,
                             257,
                             powers_to_f((257, 12, 0)))
    print('\nInitialize ECC 257\n')
    ecc257 = ECC(curve=curve257, n=0x800000000000000000000000000000006759213AF182E987D3E17714907D470D)
    print('\nRunning ECC 257\n')
    run(ecc257)
