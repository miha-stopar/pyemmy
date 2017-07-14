from Crypto.Util import number

def is_pairwise_coprime(l):
    # l is list of integers
    for i in range(len(l)):
        for j in range(i+1, len(l)):
            if number.GCD(l[i], l[j]) != 1:
                return False
    return True

def xgcd(some_a, some_b, coeff_a=[1, 0], coeff_b=[0, 1]):
        # Use sage xgcd instead!
        # Extended Euclid
        # if some_b > some_a the next iteration will get these two parameters exchanged
        some_a_x = coeff_a[0]
        some_a_y = coeff_a[1]
        some_b_x = coeff_b[0]
        some_b_y = coeff_b[1]
        #puts "#{a}, #{b}, [#{some_a_x}, #{some_a_y}], [#{some_b_x}, #{some_b_y}]"
        # some_a = some_a_x * a + some_a_y * b
        # some_b = some_b_x * a + some_b_y * b
        if some_b == 0:
            return [some_a, some_a_x, some_a_y]
        k1 = some_a / some_b
        r1 = some_a % some_b
        # express remainder as a pair of coefficients of the current some_a and some_b
        #r1 = some_a - some_b * k1 
        #r1 = some_a_x * a + some_a_y * b - (some_b_x * a + some_b_y * b) * k1
        #r1 = (some_a_x - some_b_x * k1) * a + (some_a_y - some_b_y * k1) * b
        coeff = xgcd(some_b, r1, [some_b_x, some_b_y], [some_a_x-some_b_x*k1, some_a_y-some_b_y*k1])
        return coeff
    
    
    
    