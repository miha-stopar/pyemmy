from Crypto.Util import number

class Z_m():
    def __init__(self, m, order):
        self.m = m
        self.order = order
        self.rules = {}
                
    def exponentiate(self, x, y):
        if y >= 0:
            r = pow(x, y, self.m)
        else:
            r = pow(x, -y, self.m)
            r = self.get_inverse(r)
        return r
    
    def get_inverse(self, x):
        inv = number.inverse(x, self.m) 
        return inv
    
    def get_generator_of_zn_subgroup(self, subgroup_order):
        """
        It returns a generator of a subgroup of a specified order in Z_n.
        Parameter group_order is order of Z_n (if n is prime, order is n-1).
        """
        if self.order % subgroup_order != 0:
            return None
        r = self.order / subgroup_order
        while True:
            h = number.getRandomRange(0, self.m)
            g = pow(h, r, self.m)
            if g != 1:
                return g
        
class Z_pq(Z_m):
    """ n = p * q, where p and q are two different primes
    """
    def __init__(self, p, q):
        n = p * q
        Z_m.__init__(self, n, (p-1) * (q-1))
        self.p = p
        self.q = q
    
    def check(self, x):
        # we cannot find x which is a multiple of p or q
        if x % self.p == 0:
            return False
        if x % self.q == 0:
            return False
        
        return True

class Z_paillier(Z_m):
    """
    Z_n^2 where n = p * q, p and q are 
    safe primes (p = 2*p1 + 1, q = 2*q1 + 1 where p1 and q1 are primes).
    It is called Paillier because Paillier [1] encryption uses Z_n^2 where n is of the form above.
    
    [1] P. Paillier, Public-key cryptosystems based on composite residuosity classes, 
    Advances in Cryptology - EUROCRYPT 99 (J. Stern, ed.), LNCS, vol. 1592, Springer Verlag, 1999,
    pp. 223-239.
    """
    def __init__(self, p1, q1):
        p = 2 * p1 + 1
        q = 2 * q1 + 1
        n = p * q
        n2 = n * n
        order = n * (p-1) * (q-1)
        Z_m.__init__(self, n2, order)
        self.p1 = p1
        self.q1 = q1
        self.p = p
        self.q = q
        
        
    
    
    
    
    
        
        
        
        
        