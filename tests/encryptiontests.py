from emmy.encryption.cspaillier import CSPaillier

sec_params = {"l": 512, "dlog_length": 1024, "k": 158, "k1": 158}
paillier = CSPaillier(sec_params)

m = 242342342
L = 909807
u, e, v = paillier.encrypt(m, L)
#print("%s, %s, %s" % (u, e, v))
print(u)
print(e)
print(v)

m_test = paillier.decrypt(u, e, v, L)
print(m)
print(m_test)


