import random
from sympy import mod_inverse

# ----------------- Tonelli-Shanks Algorithm -----------------
# Function to find modular square root of n mod p using Tonelli-Shanks algorithm

def tonelli_shanks(n, p):
  x = p-1
  s = 0
  while x%2!=1:
    x=x//2
    s+=1
  q = (p-1)//(2**s)

  # Find a non-residue 'z' modulo p

  z = 2
  while(isResidue(z,p)):
    z+=1

  # Initialization

  M = s
  c = pow(z,q,p)
  t = pow(n,q,p)
  R = pow(n,(q+1)//2,p)
  while(True):
    if(t==0):
      return 0
    if(t==1):
      return R
    i = 0
    while(pow(t,2**i,p)!=1):
      i+=1
    b = pow(c,2**(M-i-1),p)
    M = i
    c = pow(b,2,p)
    t = (t*c)%p
    R = (R*b)%p

# ----------------- Modular Exponentiation -----------------
# Custom modular exponentiation function

def pow(a, b, m):
    # print(f"**** pow *****")
    if(b == 0):
      return 1%m
    ans = pow(a, b//2, m)
    if(b%2 == 0):
      return (ans*ans)%m
    else:
      return ((ans*ans)%m*a)%m


# ----------------- Check if number is a quadratic residue mod p -----------------

def isResidue(x, p):
  # print(f"**** isResidue *****")
  return pow(x,(p-1)//2,p) == 1

# ----------------- Generate elliptic curve points y² = x³ + ax + d mod p for x in range (0,1000) -----------------

def generatePoints(a, d, p, start=0):
  #Creating the output file
  x_array = []
  y_array = []

  # $$$
  if start > p:
    start = 0

  # take at max 1000 points
  for x in range(start,  min(start +1000, p)):
      fx = ((x*x*x)+(a*x)+d)%p   #finding values of y^2 mod p for every integer value of x in range
      if(isResidue(fx, p) or fx == 0):
        # 4k+3 form
        if((p-3)%4 == 0):
          y = pow(fx, (p+1)//4, p)   #euler's method
        # 4k+1 form
        else:
          y = tonelli_shanks(fx,p)   #Tonneli-Shank's method

        x_array.append(x)
        y_array.append(y)
        if fx != 0:
          x_array.append(x)
          y_array.append(p-y)
  return (x_array,y_array)


# ----------------- Count number of valid points on curve if p<=100003 -----------------
def generatePointsUpto99999(a, d, p, start=0):
  #Creating the output file
  x_array = []
  y_array = []

  # $$$
  if start > p:
    start = 0

  for x in range(start,  p):
      fx = ((x*x*x)+(a*x)+d)%p   #finding values of y^2 mod p for every integer value of x in range
      if(isResidue(fx, p) or fx == 0):
        # 4k+3 form
        if((p-3)%4 == 0):
          y = pow(fx, (p+1)//4, p)   #euler's method
        # 4k+1 form
        else:
          y = tonelli_shanks(fx,p)   #Tonneli-Shank's method

        x_array.append(x)
        y_array.append(y)
        if fx != 0:
          x_array.append(x)
          y_array.append(p-y)
  return len(x_array)

# ----------------- Count number of valid points on curve if p>100003 -----------------
def func_no_of_generator_point(a,b,p,array):
    lo = int(p + 1 - 2*(p**0.5))
    hi = int(p + 1 + 2*(p**0.5))
    tinycurve = No_of_point(p,a,b,len(array[0])+1)


    set_n = set()
    no_of_points = lo

    maxi = 0
    for t in range(1, 10):
        # Ensure unique random index
        n = random.randint(0, len(array[0]) - 1)
        set_n.add(n)
        while n in set_n:
            set_n.add(n)
            n = random.randint(0, len(array[0]) - 1)

        i, j = array[0][n], array[1][n]
        count = lo
        for k in range( lo, hi):
            result = tinycurve.mult(k, (i, j))
            result2 = tinycurve.mult(k+1, (i, j))
            if result == None and result2==(i,j):
                no_of_points = max(no_of_points, count)
                break  # Stop checking further for this point
            count+=1
    return no_of_points


# ----------------- No_of_point Class -----------------
# Class to do various operations on points

class No_of_point:
    """An elliptic curve over a prime field.

    The field is specified by the parameter 'p'.
    The curve coefficients are 'a' and 'b'.
    The base point of the cyclic subgroup is 'g'.
    The order of the subgroup is 'n'.
    """

    def __init__(self, p, a, b, n):
        self.p = p
        self.a = a
        self.b = b
        self.n = n

        assert pow(2, p - 1, p) == 1

    def is_on_curve(self, point):
        """Checks whether the given point lies on the elliptic curve."""
        if point is None:
            return True

        x, y = point
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    def add(self, point1, point2):
        """Returns the result of point1 + point2 according to the group law."""

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
        if self.n >0 :
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

