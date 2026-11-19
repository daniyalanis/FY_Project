#######################################################################
#
# Name       : Imamul Hasan 
# Roll No    : 002111001042
# Team No    : Group 22
# Date       : 14.03.2025
#
# Assignment : Find the generator points of Elliptic curve
# 
#
# Input      : 
#   - Elliptic Curve parameters a, b, p (prime modulus)
#
#
# Output     : 
#   - Generator Points
#   - No. of generator Points
#   - Time taken to find generator points of the curve
#
# Compilation Command :
#     No compilation needed (Python script)
#
#
# Execution Command :
#   python3 generator_points.py 2 3 17
#
#
# Sample Input:
#   a = 2, b = 3, p = 17
#
# Sample Output:
#       Called with a=2, b=3, p=17
#       (2,7) is a generator
#       (2,10) is a generator
#       (5,6) is a generator
#       (5,11) is a generator
#       (9,6) is a generator
#       (9,11) is a generator
#       (11,8) is a generator
#       (11,9) is a generator
#       (13,4) is a generator
#       (13,13) is a generator
#       Total no of generator points 10
#       Time taken: 0.0014 seconds
#
#######################################################################

from common import *
from sympy import nextprime
import time
import sys

# ----------------- EllipticCurve Class -----------------
# EllipticCurve Class to do various operations on points such as add, double, negative, multiply
class EllipticCurve:
    """An elliptic curve over a prime field.

    The field is specified by the parameter 'p'.
    The curve coefficients are 'a' and 'b'.
    The base point of the cyclic subgroup is 'g'.
    The order of the subgroup is 'n'.
    """

    def __init__(self, p, a, b, g, n):
        self.p = p
        self.a = a
        self.b = b
        self.g = g
        self.n = n

        assert pow(2, p - 1, p) == 1
        assert self.mult(n, g) is None

    def is_on_curve(self, point):
        """Checks whether the given point lies on the elliptic curve."""
        if point is None:
            return True

        x, y = point
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    def add(self, point1, point2):
        """Returns the result of point1 + point2 according to the group law."""
        assert self.is_on_curve(point1)
        assert self.is_on_curve(point2)

        if point1 is None:
            return point2
        if point2 is None:
            return point1

        x1, y1 = point1
        x2, y2 = point2

        if x1 == x2 and y1 != y2:
            return None

        if x1 == x2:
            if y1==0:
                return None
            m = (3 * x1 * x1 + self.a) * mod_inverse(2 * y1, self.p)%self.p
        else:
            m = (y1 - y2) * mod_inverse(x1 - x2, self.p)%self.p

        x3 = m * m - x1 - x2
        y3 = y1 + m * (x3 - x1)
        result = (x3 % self.p,
                  -y3 % self.p)

        assert self.is_on_curve(result)

        return result

    def double(self, point):
        """Returns 2 * point."""
        return self.add(point, point)

    def neg(self, point):
        """Returns -point."""
        if point is None:
            return None

        x, y = point
        result = x, -y % self.p

        assert self.is_on_curve(result)

        return result

    def mult(self, n, point):
        """Returns n * point computed using the double and add algorithm."""
        if n % self.n == 0 or point is None:
            return None

        if n < 0:
            return self.neg(self.mult(-n, point))

        result = None
        addend = point

        while n:
            if n & 1:
                result = self.add(result, addend)
            addend = self.double(addend)
            n >>= 1

        return result

    def __str__(self):
        a = abs(self.a)
        b = abs(self.b)
        a_sign = '-' if self.a < 0 else '+'
        b_sign = '-' if self.b < 0 else '+'

        return 'y^2 = (x^3 {} {}x {} {}) mod {}'.format(
            a_sign, a, b_sign, b, self.p)


# ----------------- compute_order function to calculate the order of the point (x,y) when p >= 100 -----------------
def compute_order(curve, P, N):
    """Computes the order n of point P, given N = #E(F_p)."""
    # print(f"**** Compute Order *****")
    if P is None:
        return 1  # Order of the point at infinity is 1

    # Step 1: Factorize N into its prime factors
    def factorize(n):
        factors = []
        # Handle 2 separately
        while n % 2 == 0:
            factors.append(2)
            n = n // 2
        # Check odd divisors up to sqrt(n)
        i = 3
        while i * i <= n:
            while n % i == 0:
                factors.append(i)
                n = n // i
            i += 2
        if n > 1:
            factors.append(n)
        return factors

    prime_factors = factorize(N)

    # Step 2: Generate all divisors of N in sorted order
    def get_divisors(factors):
        divisors = [1]
        for p in factors:
            new_divisors = []
            for d in divisors:
                new_divisors.append(d * p)
            divisors += new_divisors
        return sorted(set(divisors))  # Remove duplicates and sort

    divisors = get_divisors(prime_factors)

    # Step 3: Find the smallest d where dP = O
    for d in divisors:
        if curve.mult(d, P) is None:
            return d


    return N  # Fallback (if P is a generator, n = N)

# ----------------- point_order function to calculate the order of the point (x,y) when p < 100 -----------------
def point_order(curve, xp, yp):
    xq, yq = xp, yp
    point = curve.add( (xq, yq) , (xq, yq) )  # First doubling
    if point==None:
        return 1
    xr, yr = point
    order = 2

    while (xr != xp or yr != yp):
        xq, yq = xr, yr
        point = curve.add( ( xp, yp) , ( xq, yq) )
        order += 1

        if point == None:
            return order

        xr, yr = point

    return order


# ----------------- Generate generator points of the elliptic curve y² = x³ + ax + d mod p for x in range (0,1000) -----------------
def points(a, b, p, N, array):
    count = 0
    result = [[],[]]
    for i, j in zip(array[0], array[1]):
        tinycurve = EllipticCurve(p, a, b, g=(i, j), n=N, )

        try:
            # Compute its order
            if p<99:
                n = point_order(tinycurve, i, j)
            else:
                n = compute_order(tinycurve, (i, j), N)
            if n == N:
                print(f"({i},{j}) is a generator")
                result[0].append(i)
                result[1].append(j)
                count += 1
        except:
            continue
    print(f"Total no of generator points {count}")
    return result

# ----------------- Main Entry Point -----------------

if len(sys.argv) != 4:
    print("Usage: python3 generator_points.py <arg1> <arg2> <arg3> ")
    sys.exit(1)

# Read arguments from command line
a = int(sys.argv[1]) #a
b = int(sys.argv[2]) #b
p = int(sys.argv[3]) #p

start = time.time()  # ⏱️ Start timer

# Checking and assignment of prime value p
q = nextprime(p-1)
if p!=q:
   print(f'p = {p} is not a prime number taking next prime {q}')
   p=q
print(f"Called with a={a}, b={b}, p={p}")

# if-else for faster results
if p<99999:
    N = generatePointsUpto99999(a,b,p) + 1
else:
    array = generatePoints(a,b,p)
    N = func_no_of_generator_point(a,b,p,array)

# N = 1000004178

# ----------------- Generate number of valid points on curve for x in (0,1000) -----------------
array = generatePoints(a, b, p)

# ----------------- Generate number of valid generator points on curve for x in (0,1000) -----------------
gen_points = points(a, b, p, N, array)
        
end = time.time()

# Output results
print(f"Time taken: {end - start:.4f} seconds")