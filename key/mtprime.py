from hashlib import sha512

class MT19937Prime():
    def __init__(self, seed: int = 0):
        # HERE BE CONSTANTS
        self.w = 32
        self.n = 624
        self.m = 397
        self.r = 31
        self.a = 0x9908b0df
        self.u = 11
        self.d = 0xffffffff
        self.s = 7
        self.b = 0x9d2c5680
        self.t = 15
        self.c = 0xefc60000
        self.l = 18
        self.f = 1812433253
        self.MT = [0 for _ in range(self.n)]
        self.lower_mask = (1<<self.r)-1
        self.upper_mask = 0x00000000
        self.index = self.n+1
        self.seed_mt(seed)

    def seed_mt(self, seed: int):
        self.index = self.n
        self.MT[0] = seed
        for i in range(1, self.n):
            t = self.f * (self.MT[i-1] ^ (self.MT[i-1] >> (self.w-2))) + i
            self.MT[i] = t & 0xffffffff

    def _twist(self):
        for i in range(0, self.n):
            x = (self.MT[i] & self.upper_mask) + (self.MT[(i+1)%self.n] & self.lower_mask)
            xA = x >> 1
            if not (x%2) == 0:
                xA = xA ^ self.a
            self.MT[i] = self.MT[(i+self.m) % self.n] ^ xA

        self.index = 0

    # extract a tempered value based on MT[index]
    # calling twist() every n numbers
    def extract_number(self) -> int:
        if self.index >= self.n:
            if self.index > self.n:
                self.seed_mt(5489)
            self._twist()

        # Good luck with this!
        h = sha512()
        y = self.MT[self.index]
        y = y ^ ((y >> self.u) & self.d)
        h.update(y.to_bytes(8, byteorder='big'))
        y = (int.from_bytes(h.digest(), "big") >> 16) & ((1<<32)-1)
        y = y ^ ((y << self.s) & self.b)
        h.update(y.to_bytes(8, byteorder='big'))
        y = (int.from_bytes(h.digest(), "big") >> 16) & ((1<<32)-1)
        y = y ^ ((y << self.t) & self.c)
        h.update(y.to_bytes(8, byteorder='big'))
        y = (int.from_bytes(h.digest(), "big") >> 16) & ((1<<32)-1)
        y = y ^ (y >> 1)
        self.index += 1
        return y & 0xffffffff

    def randbelow(self, start: int) -> int:
        return self.extract_number() % start

    def randrange(self, start: int, stop: int = None):
        if stop is None:
            return self.randbelow(start)
        else:
            width = stop - start
            return start + self.randbelow(width)