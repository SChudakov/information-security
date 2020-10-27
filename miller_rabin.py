import random


class MillerRabin:
    _default_k = 100

    @staticmethod
    def is_prime(n: int, k: int = _default_k) -> bool:
        assert n > 0
        assert k > 0
        if n == 1:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        r = 0
        d = n - 1
        while r % 2 == 0:
            r += 1
            d //= 2
        for _ in range(k):
            a = random.randint(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
