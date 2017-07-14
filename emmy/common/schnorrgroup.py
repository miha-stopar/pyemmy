from Crypto.PublicKey import DSA
from emmy.common.zn import Z_m

class SchnorrGroup(Z_m):
    def __init__(self, p_length = None, p = None, q = None, g = None):
        if p == None:
            dsa = DSA.generate(p_length)
            self.p = dsa.p
            self.q = dsa.q
            self.g = dsa.g
        else:
            self.p = p
            self.q = q
            self.g = g
        Z_m.__init__(self, self.p, self.q)
        
    def exponentiate_base_g(self, x):
        """
        Computes g^x % p
        """
        r = pow(self.g, x, self.p)
        return r
    