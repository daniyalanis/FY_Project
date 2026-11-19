#######################################################################
#
# Name       : Md Shahnawaaz Ansari  
# Roll No    : 002111001036
# Team No    : Group 3
# Date       : 14.03.2025
#
# Assignment : Implementation of the Baby-Step Giant-Step (BSGS) Algorithm 
#              for solving the Elliptic Curve Discrete Logarithm Problem (ECDLP)
# 
#
# Input      : 
#   - Elliptic Curve parameters a, b, p (prime modulus)
#   - Coordinates of point P (base point)
#   - Coordinates of point Q (resultant point Q = kP)
#
#
# Output     : 
#   - Discrete logarithm k such that Q = kP
#   - Time taken to compute the discrete log
#
# Compilation Command :
#     No compilation needed (Python script)
#
#
# Execution Command :
#   python3 bsgs.py 2 1 983 38 282 46 657
#
#
# Sample Input:
#   a = 2, b = 1, p = 983
#   P = (38, 282)
#   Q = (46, 657)
#
# Sample Output:
#   Called with a=2, d=1, p=983
#   Point P is (38, 282)
#   Point Q is (46, 657)
#   Discrete value Q = kP, k = 25
#   Time taken: 0.0209 seconds
#
#######################################################################


import sys
import time

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
  R = pow(n,(q+1)/2,p)
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
  return pow(x,(p-1)/2,p) == 1

# ----------------- Generate elliptic curve points y² = x³ + ax + d mod p -----------------

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
          y = pow(fx, (p+1)/4, p)   #euler's method
        # 4k+1 form
        else:
          y = tonelli_shanks(fx,p)   #Tonneli-Shank's method

        x_array.append(x)
        y_array.append(y)
        if fx != 0:
          x_array.append(x)
          y_array.append(p-y)
  return (x_array,y_array)

# Generate up to p points

def generatePointsUpto99999(a, d, p, start=0):
  #Creating the output file
  x_array = []
  y_array = []

  # $$$
  if start > p:
    start = 0

  # take at max 1000 points
  for x in range(start,  p):
      fx = ((x*x*x)+(a*x)+d)%p   #finding values of y^2 mod p for every integer value of x in range
      if(isResidue(fx, p) or fx == 0):
        # 4k+3 form
        if((p-3)%4 == 0):
          y = pow(fx, (p+1)/4, p)   #euler's method
        # 4k+1 form
        else:
          y = tonelli_shanks(fx,p)   #Tonneli-Shank's method

        x_array.append(x)
        y_array.append(y)
        if fx != 0:
          x_array.append(x)
          y_array.append(p-y)
  return (x_array,y_array)

# ----------------- Count number of valid points on curve -----------------

def Num_Points(a,b,p):
    print(f"Called with a={a}, b={b}, p={p}")

    array = generatePointsUpto99999(a,b,p)
    N= len(array[0])+1
    return N

# ----------------- Extended Euclidean Algorithm for modular inverse -----------------

def extended_gcd(aa, bb):
   lastremainder, remainder = abs(aa), abs(bb)
   x, lastx, y, lasty = 0, 1, 1, 0
   while remainder:
       lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
       x, lastx = lastx - quotient*x, x
       y, lasty = lasty - quotient*y, y
   return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)
# calculate `modular inverse`
def modinv(a, m):
   g, x, y = extended_gcd(a, m)
   if g != 1:
       raise ValueError
   return x % m

# double function
def ecc_double(x1, y1, p, a):
   s = ((3*(x1**2) + a) * modinv(2*y1, p))%p
   x3 = (s**2 - x1 - x1)%p
   y3 = (s*(x1-x3) - y1)%p
   return (x3, y3)
# add function
def ecc_add(x1, y1, x2, y2, p, a):
   s = 0
   if (x1==x2) and (y1==y2):
       if y1==0:
          return None
       return ecc_double(x1, y1, p, a)
   if (x1==x2):
       s = ((3*(x1**2) + a) * modinv(2*y1, p))%p
   else:
       s = ((y2-y1) * modinv(x2-x1, p))%p
   x3 = (s**2 - x1 - x2)%p
   y3 = (s*(x1 - x3) - y1)%p
   return (x3, y3)

# ----------------- Scalar multiplication using Double-and-Add -----------------

def double_and_add(multi, generator, p, a):
   (x3, y3)=(0, 0)
   (x1, y1) = generator
   (x_tmp, y_tmp) = generator
   init = 0
   if multi == 0:
      return None
   if multi == 1:
      return (x_tmp, y_tmp)
   for i in str(bin(multi)[2:]):
       if (i=='1') and (init==0):
          init = 1
       elif (i=='1') and (init==1):
          (x3,y3) = ecc_double(x_tmp, y_tmp, p, a)
          (x3,y3) = ecc_add(x1, y1, x3, y3, p, a)
          (x_tmp, y_tmp) = (x3, y3)
       else:
          (x3, y3) = ecc_double(x_tmp, y_tmp, p, a)
          (x_tmp, y_tmp) = (x3, y3)
   return (x3, y3)

def is_on_curve(x, y, a, b, p):
    return (y**2 % p) == (x**3 + a*x + b) % p

from math import isqrt, ceil
import time

# Baby-Step Giant-Step algorithm for ECDLP
def bsgs_ecdsa(x1,y1,x2,y2, p,a,b):
    """
    Solve the ECDLP: Find k such that P = kG using Baby-Step Giant-Step.
    """
    if not is_on_curve(x1, y1, a, b, p):
        print("P is not on the curve")
        return None  # P is not on the curve
    if not is_on_curve(x2, y2, a, b, p):
        print("Q is not on the curve")
        return None  # Q is not on the curve


    # Step 1: Precompute constants
    nn = Num_Points(a, b, p)
    N = isqrt(nn) + 1

    # Step 2: Baby-step phase - Compute multiples of G up to N
    baby_steps = {}
    P = (x1,y1)

    for j in range(nn - 1 ):
        current = double_and_add(j, P, p, a)
        if current not in baby_steps:
          baby_steps[current] = j


    # Step 3: Giant-step phase - Compute P - i * (N * G)
    inv_G = double_and_add(N, P, p, a)  # Compute -N * G (mod p)
    q= (x2,y2)
    neg_mP = (inv_G[0], -inv_G[1] % p)
    current = q
    for i in range(N+1):
        if current in baby_steps:
            j = baby_steps[current]
            return i * N + j  # Solve for k
        ch=double_and_add(j, neg_mP, p, a)
        current = ecc_add(q[0],q[1],ch[0],ch[1],p,a)  # Subtract N * G

    return None  # No solution found

# ----------------- Main Entry Point -----------------

if len(sys.argv) < 8:
    print("Usage: python bsgs.py <arg1> <arg2> <arg3> <arg4> <arg5> <arg6> <arg7>")
    sys.exit(1)

# Read arguments from command line

arg1 = int(sys.argv[1]) #a
arg2 = int(sys.argv[2]) #b
arg3 = int(sys.argv[3]) #p
arg4 = int(sys.argv[4]) #x1
arg5 = int(sys.argv[5]) #y1
arg6 = int(sys.argv[6]) #x2
arg7 = int(sys.argv[7]) #y2

start = time.time()  # ⏱️ Start timer
k_found = bsgs_ecdsa(arg4,arg5,arg6,arg7,arg3,arg1,arg2)
end = time.time()

# Output results
print("Point P is (" , arg4,",",arg5,")")
print("Point Q is (" , arg6,",",arg7,")")
print("discrete value Q = KP K = ",k_found)
print(f"Time taken: {end - start:.4f} seconds")

