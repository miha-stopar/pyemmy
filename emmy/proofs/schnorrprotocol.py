from Crypto.Util import number
from emmy.common.schnorrgroup import SchnorrGroup

class SchnorrProver():
    """
    Sigma protocol for proving that you know discrete logarithm of a^s % p (s can be viewed
    as secrete key, a^s % p as public key).
    """
    def __init__(self, secret, p_length, p=None, q=None, g=None):
        self.secret = secret
        if p != None and q != None and g != None:
            self.sgroup = SchnorrGroup(None, p, q, g)
        else:
            self.sgroup = SchnorrGroup(p_length)

    def get_proof_random_data(self, secret, a):
        self.secret = secret
        self.a = a
        r = number.getRandomRange(0, self.sgroup.q)
        self.r = r
        x = self.sgroup.exponentiate(a, r)
        return x
    
    def get_proof_data(self, c):
        y = (self.r + self.secret * c) % self.sgroup.q
        return y

class SchnorrVerifier():
    def __init__(self, p, q, g):
        self.sgroup = SchnorrGroup(None, p, q, g)

    def get_challenge(self, x, a, b):
        self.x = x
        self.a = a
        self.b = b
        c = number.getRandomRange(0, self.sgroup.q)
        self.c = c
        return c
    
    def verify(self, y):
        """
        Verify that a^y = a^r * (a^secret)^c (mod p).
        """
        left = self.sgroup.exponentiate(self.a, y)
        right = (self.x * self.sgroup.exponentiate(self.b, self.c)) % self.sgroup.p
        is_ok = (left == right)
        return is_ok
            
        
