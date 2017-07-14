from emmy.encryption.cspaillier import CSPaillier

class CSPaillierProof():
    def __init__(self):
        sec_params = {"l": 512, "dlog_length": 1024, "k": 158, "k1": 158}
        
        self.decryptor = CSPaillier(sec_params)
        self.encryptor = CSPaillier(None, self.decryptor.pub_key)
    
    def prove(self, m, label):
        # We have (u, e, v) encryption of m and gamma^m in some group, we need to prove that
        # (u, e, v) is encryption of log_gamma(m).
        u, e, v = self.encryptor.encrypt(m, label)
        
        print(self.encryptor.pub_key["n"])
        print(m)
        passes = []
        for m_test in xrange(self.encryptor.pub_key["n"]):
            
            delta = self.encryptor.schnorr_group.exponentiate_base_g(m_test)
            l = self.encryptor.get_first_msg(m_test, label) # first message to be sent to the verifier
            u1, e1, v1, delta1, l1 = self.encryptor.get_proof_random_data(u, e, label)
            c = self.decryptor.get_challenge(u1, e1, v1, delta1, l1)
            r_tilde, s_tilde, m_tilde = self.encryptor.get_proof_data(c)
        
            is_ok = self.decryptor.verify(u, e, v, label, delta, l, r_tilde, s_tilde, m_tilde)
            if is_ok:
                passes.append(m_test)
        print(passes)
       
    
    
    