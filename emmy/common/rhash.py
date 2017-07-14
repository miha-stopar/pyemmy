from Crypto.Hash import SHA512
from Crypto.Util import number

class RHash():
    def __init__(self):
        pass

    def concatenate(self, l):
        c = ""
        for i in l:
            b = number.long_to_bytes(i)
            c += b
        c_long = number.bytes_to_long(c)
        return c_long
        
    def hash(self, x):
        # x is integer
        h = SHA512.new()
        h.update(hex(x))
        b = h.hexdigest()
        return int(b, 16)
        