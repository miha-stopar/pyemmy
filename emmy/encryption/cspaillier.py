import sys
from Crypto.Util import number
import gensafeprime

from emmy.common.schnorrgroup import SchnorrGroup
from emmy.common.rhash import RHash
from emmy.common.zn import Z_m

class VerifiableEncGroup(Z_m):
    def __init__(self, n, n1, g1=None, h1=None):
        if g1 == None and h1 == None:
            Z_m.__init__(self, n, n1)
            self.g1 = self.get_generator_of_zn_subgroup(n1)
            self.h1 = self.get_generator_of_zn_subgroup(n1)
        else:
            self.g1 = g1 
            self.h1 = h1 
            self.m = n
        
    def get_msg(self, msg):
        s = number.getRandomRange(0, self.m / 4)
        # l = g1^msg * h1^s
        t1 = pow(self.g1, msg, self.m)
        t2 = pow(self.h1, s, self.m)
        l = t1 * t2
        # s is computed in this verifiable_enc_group because it depends on self.m
        return s, l

class CSPaillier(Z_m):
    """ 
    Security parameter dlog_length denotes here bit length of p in Schnorr group (in paper
    ro_length is specified as bit length of q).
    """
    def __init__(self, sec_params, pub_key=None):
        self.sec_params = sec_params
        self.pub_key = {}
        self.sec_key = {}
        self.enc_data = {} # for encryptor it contains m and r
        # proof_random_data: for encryptor it contains r1, s1, m1;
        # for decryptor it contains c, u1, e1, v1, delta1, l1
        self.proof_random_data = {} 
        if pub_key == None:
            success = self.generate_key()
            if not success:
                print("CS Paillier initialization failed")
                return
            self.schnorr_group = SchnorrGroup(sec_params["dlog_length"])
        
            # it must hold:
            # 2**K < min{p1, q1, ro}; ro is Gamma.OrderOfSubgroup
            # ro * 2**(K + K1 + 3) < n
            k = self.sec_params["k"]
            k1 = self.sec_params["k1"]
            if 2**k >= min(self.p1, self.q1, self.schnorr_group.q):
                sys.exit("parameter k is not valid")
            if self.schnorr_group.q * 2**(k + k1 + 3) >= self.pub_key["n"]:
                sys.exit("parameters k or k' are not valid")
            self.pub_key["k"] = k
            self.pub_key["k1"] = k1
            self.pub_key["dlog_p"] = self.schnorr_group.p
            self.pub_key["dlog_q"] = self.schnorr_group.q
            self.pub_key["dlog_g"] = self.schnorr_group.g
                
            # We need to compute two generators in Z_n* subgroup of order n1.
            # Note that here a different n might be used from the one in encryption, 
            # however here we use the same (the paper says it can be the same).
            self.verifiable_enc_group = VerifiableEncGroup(self.pub_key["n"], self.p1 * self.q1)
            self.pub_key["verifiable_enc_group_n"] = self.verifiable_enc_group.m
            self.pub_key["verifiable_enc_group_g1"] = self.verifiable_enc_group.g1
            self.pub_key["verifiable_enc_group_h1"] = self.verifiable_enc_group.h1
            
            order = self.pub_key["n"] * (self.p-1) * (self.q-1)
            n2 = self.pub_key["n"] * self.pub_key["n"]
            Z_m.__init__(self, n2, order)
        else:
            self.pub_key = pub_key
            self.schnorr_group = SchnorrGroup(None, pub_key["dlog_p"], 
                                    pub_key["dlog_q"], pub_key["dlog_g"])
            self.verifiable_enc_group = VerifiableEncGroup(pub_key["verifiable_enc_group_n"], None,
                                                           pub_key["verifiable_enc_group_g1"],
                                                           pub_key["verifiable_enc_group_h1"])
            n2 = self.pub_key["n"] * self.pub_key["n"]
            # we don't know the order here
            Z_m.__init__(self, n2, None)
    
    def encrypt(self, m, L):
        if m >= self.pub_key["n"]:
            print("message m too large")
            return None
        r = number.getRandomRange(0, self.pub_key["n"] / 4)
        self.enc_data["r"] = r
        self.enc_data["m"] = m
        n2 = self.pub_key["n"] * self.pub_key["n"]
        
        # u = g^r % n2
        u = pow(self.pub_key["g"], r, n2)
        
        # e = y1^r * h^m % n2
        e1 = pow(self.pub_key["y1"], r, n2)
        h = 1 + self.pub_key["n"]
        e2 = pow(h, m, n2)
        e = e1 * e2 % n2
        
        # v = abs((y2 * y3^hash(u, e, L))^r)
        rhash = RHash()
        to_be_hashed = rhash.concatenate([u, e, L])
        rh = rhash.hash(to_be_hashed)
        t = pow(self.pub_key["y3"], rh, n2)
        t = self.pub_key["y2"] * t % n2
        t = pow(t, r, n2)
        v = self.abs(t)
        return u, e, v
    
    def decrypt(self, u, e, v, L):
        if abs(v) != v:
            print("ciphertext not valid 1")
            return None
        #check whether u^(2 * (x2 + hash(u, e, L) * x3)) = v^2:
        rhash = RHash()
        to_be_hashed = rhash.concatenate([u, e, L])
        rh = rhash.hash(to_be_hashed)
        t = 2 * (rh * self.sec_key["x3"] + self.sec_key["x2"])
        n2 = self.sec_key["n"] * self.sec_key["n"]
        if pow(u, t, n2) != pow(v, 2, n2):
            print("ciphertext not valid 2")
            return None
        # m1 = e / u^x1
        ux1 = pow(u, self.sec_key["x1"], n2)
        ux1_inv = self.get_inverse(ux1)
        m1 = (e * ux1_inv) % n2
        # m1 = 1 + m * n
        if (m1 - 1) % self.sec_key["n"] != 0:
            print("ciphertext not valid 3")
            return None
        m  = (m1 - 1) / self.sec_key["n"]
        return m
        
    def abs(self, x): 
        n2 = self.pub_key["n"] * self.pub_key["n"]
        if x > n2 / 2:
            return n2 - x
        else:
            return x
        
    def generate_key(self):
        # l is length of p1 and q1
        # (l+1) is length of p and q
        # n = p * q -> length of n is 2*(l+1)
        safeprime_length = self.sec_params["l"] + 1
        self.p = gensafeprime.generate(safeprime_length)
        self.q = gensafeprime.generate(safeprime_length)
        
        self.p1 = (self.p - 1) / 2
        self.q1 = (self.q - 1) / 2
        #if self.p1 == self.q1:
        #    sys.exit("p1 and q1 are the same")
        
        n = self.p * self.q
        self.pub_key["n"] = n
        n2 = n * n
        # n1 = self.p1 * self.q1
        
        gg1 = number.getRandomRange(0, n2) # g' in paper
        g = pow(gg1, 2*n, n2)
        self.pub_key["g"] = g
        
        # choose x1, x2, x3 which are < n^2/4
        b = n2 / 4
        x1 = number.getRandomRange(0, b)
        x2 = number.getRandomRange(0, b)
        x3 = number.getRandomRange(0, b)
        self.sec_key["n"] = n
        self.sec_key["g"] = g
        self.sec_key["x1"] = x1
        self.sec_key["x2"] = x2
        self.sec_key["x3"] = x3
        
        y1 = pow(g, x1, n2)
        y2 = pow(g, x2, n2)
        y3 = pow(g, x3, n2)
        
        self.pub_key["y1"] = y1
        self.pub_key["y2"] = y2
        self.pub_key["y3"] = y3  
        return True
            
    def get_first_msg(self, m, L):
        s, l = self.verifiable_enc_group.get_msg(m)
        self.proof_random_data["s"] = s
        return l
    
    def get_proof_random_data(self, u, e, L):
        # choose r1 from [-n*2^(k+k1-2), n*2^(k+k1-2)]
        k = self.pub_key["k"]
        k1 = self.pub_key["k1"]
        b1 = self.pub_key["n"] * 2**(k+k1-2)
        r1 = number.getRandomRange(-b1, b1)
        
        # choose s1 from [-n*2^(k+k1-2), n*2^(k+k1-2)], where n is the one used in verifiable enc group
        b2 = self.pub_key["verifiable_enc_group_n"] * 2**(k+k1-2)
        s1 = number.getRandomRange(-b2, b2)
        
        # choose m1 from [-ro * 2^(k+k'), ro * 2^(k+k')]
        b3 = self.pub_key["dlog_q"] * 2**(k+k1)
        m1 = number.getRandomRange(-b3, b3)
        
        n2 = self.pub_key["n"] * self.pub_key["n"]
        # u1 = g^(2*r1)
        u1 = self.exponentiate(self.pub_key["g"], 2*r1)
        
        # e1 = y1^(2*r1) * h^(2*m1)
        h = 1 + self.pub_key["n"]
        e11 = self.exponentiate(self.pub_key["y1"], 2*r1)
        e12 = self.exponentiate(h, 2*m1)
        e1 = (e11 * e12) % n2
        
        # v1 = (y2 * y3^hash(u, e, L))^(2*r1)
        rhash = RHash()
        to_be_hashed = rhash.concatenate([u, e, L])
        rh = rhash.hash(to_be_hashed)
        v11 = self.pub_key["y2"] * self.exponentiate(self.pub_key["y3"], rh)
        v11 = v11 % n2
        v1 = self.exponentiate(v11, 2*r1)
        
        # delta1 = gamma^m1
        delta1 = self.schnorr_group.exponentiate(self.pub_key["dlog_g"], m1)
            
        # l1 = g1^m1 * h1^s1
        l11 = self.verifiable_enc_group.exponentiate(self.pub_key["verifiable_enc_group_g1"], m1)
        l12 = self.verifiable_enc_group.exponentiate(self.pub_key["verifiable_enc_group_h1"], s1)
        l1 = (l11 * l12) % self.pub_key["verifiable_enc_group_n"]
        
        self.proof_random_data["r1"] = r1
        self.proof_random_data["m1"] = m1
        self.proof_random_data["s1"] = s1
        return u1, e1, v1, delta1, l1
    
    def get_proof_data(self, c):
        r_tilde = self.proof_random_data["r1"] - c * self.enc_data["r"]
        s_tilde = self.proof_random_data["s1"] - c * self.proof_random_data["s"]
        m_tilde = self.proof_random_data["m1"] - c * self.enc_data["m"]
        return r_tilde, s_tilde, m_tilde
        
    def get_challenge(self, u1, e1, v1, delta1, l1):
        self.proof_random_data["u1"] = u1
        self.proof_random_data["e1"] = e1
        self.proof_random_data["v1"] = v1
        self.proof_random_data["delta1"] = delta1
        self.proof_random_data["l1"] = l1
        c = number.getRandomRange(0, 2**self.pub_key["k"])
        self.proof_random_data["c"] = c
        return c
        
    def verify(self, u, e, v, label, delta, l, r_tilde, s_tilde, m_tilde):
        n2 = self.pub_key["n"] * self.pub_key["n"]
        # check if u1 = u^(2*c) * g^(2*r_tilde)
        c = self.proof_random_data["c"]
        t1 = self.exponentiate(u, 2*c)
        t2 = self.exponentiate(self.pub_key["g"], 2*r_tilde)
        t = (t1 * t2) % n2
        if self.proof_random_data["u1"] != t:
            return False
        
        # check if e1 = e^(2*c) * y1^(2*r_tilde) * h^(2*m_tilde)
        t1 = self.exponentiate(e, 2*c) * self.exponentiate(self.pub_key["y1"], 2*r_tilde)
        h = 1 + self.pub_key["n"]
        t2 = self.exponentiate(h, 2*m_tilde)
        t = (t1 * t2) % n2
        if self.proof_random_data["e1"] != t:
            return False
        
        # check if v1 = v^(2*c) * (y2 * y3^hash(u, e, L))^(2*r_tilde)
        t1 = self.exponentiate(v, 2*c)
        rhash = RHash()
        to_be_hashed = rhash.concatenate([u, e, label])
        rh = rhash.hash(to_be_hashed)
        t21 = self.pub_key["y2"] * self.exponentiate(self.pub_key["y3"], rh)
        t2 = self.exponentiate(t21, 2*r_tilde)
        t = (self.exponentiate(v, 2*c) * t2) % n2
        if self.proof_random_data["v1"] != t:
            return False
        
        # check if delta1 = delta^c * gamma^m_tilde
        t1 = self.schnorr_group.exponentiate(delta, c)
        t2 = self.schnorr_group.exponentiate(self.pub_key["dlog_g"], m_tilde)
        t = (t1 * t2) % self.pub_key["dlog_p"] 
        if self.proof_random_data["delta1"] != t:
            return False
        
        # check if l1 = l^c * g1^m_tilde * h1^s_tilde
        t1 = self.verifiable_enc_group.exponentiate(l, c)
        t2 = self.verifiable_enc_group.exponentiate(
                self.pub_key["verifiable_enc_group_g1"], m_tilde)
        t3 = self.verifiable_enc_group.exponentiate(
                self.pub_key["verifiable_enc_group_h1"], s_tilde)
        t = (t1 * t2 * t3) % self.pub_key["verifiable_enc_group_n"] 
        if self.proof_random_data["l1"] != t:
            return False
        
        # check if -n/4 < m_tilde < n/4
        b = self.pub_key["n"] / 4
        if abs(m_tilde) >= b:
            return False
        
        return True  
        