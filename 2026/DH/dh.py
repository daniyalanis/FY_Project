'''
5 September 2025

Authors:
- Ayush Rakwal
- Baleshwar Singh
- Dipankar Dutta

Usage: sage dh.py <Base_Field> <Degree> <Choice_of_Coeff> <Coeff_a1> <Coeff_a2> <Coeff_a3> <Coeff_a4> <Coeff_a6> <Sender_Name> <Receiver_Name>

About:
This program will help simulate the Diffie-Hellman Key Exchange using Elliptic Curve over GF(p) or GF(p^n) between two users. 
This program will help create an Elliptic Curve with common curve parameters and generator point. The public key generated on either side is exchanged and the shared key is given as output (along with other curve parameters and the keys generated). 

The Elliptic Curve Equation being used is:
y^2 + Coeff_a1*xy+ Coeff_a3*y = x^3 + Coeff_a2*x^2 + Coeff_a4*x + Coeff_a6

The argument of Choice_of_Coeff tells whether the Coeff's will be taken from command line or not. 
If Choice_of_Coeff is 0: All Coefficients are taken from command line arguments.
If Choice_of_Coeff is 1: All Coefficients are set to random element taken from the Base Field or Extended Field.


NOTE: The provision for cleanp has been removed and thus, manual intervention is needed to cleanup the txt file. 

'''
'''
Sample Input/Output Sets

Example 1:
Execution command on alice side: sage dh.py 9739 1 0 0 0 0 497 1768 alice bob
Execution command on bob side: sage dh.py 9739 1 0 0 0 0 497 1768 bob alice

Input 1:
Base_Field= 9739
Degree= 1
Choice_of_coeff= 0
coeff_a1= 0
coeff_a2= 0
coeff_a3= 0
coeff_a4= 497
coeff_a6= 1768

Participant_1= alice
Participant_2= bob

Output 1:
alice side output:
Sender: alice
Receiver: bob
No of generator: 1
Base Field: 9739 and Degree: 1
Curve order: 9735
Generator: (1804 : 5368 : 1)
Elliptic Curve: Elliptic Curve defined by y^2 = x^3 + 497*x + 1768 over Finite Field of size 9739
alice Private Key: 6431
alice Public Key: (3597 : 5883 : 1)
alice shared key: (2681 : 7959 : 1)

bob side output:
Sender: bob
Receiver: alice
No of generator: 1
Base Field: 9739 and Degree: 1
Curve order: 9735
Generator: (1804 : 5368 : 1)
Elliptic Curve: Elliptic Curve defined by y^2 = x^3 + 497*x + 1768 over Finite Field of size 9739
bob Private Key: 8403
bob Public Key: (7483 : 7392 : 1)
bob shared key: (2681 : 7959 : 1)


Example 2:

Execution command on alice side: sage dh.py 43 2 1 alice bob
Execution command on bob side: sage dh.py 43 2 1 bob alice

Input 2:
Base_Field= 43
Degree= 2 
Choice_of_coeff= 1

Participant_1= alice
Participant_2= bob

alice side output:
Sender: alice
Receiver: bob
No of generator: 1
Base Field: 43 and Degree: 2
Curve order: 1836
Generator: (31*a + 9 : 32*a : 1)
Elliptic Curve: Elliptic Curve defined by y^2 + (37*a+39)*x*y + (6*a+32)*y = x^3 + (a+41)*x^2 + (39*a+2)*x + (20*a+6) over Finite Field in a of size 43^2
alice Private Key: 737
alice Public Key: (3*a + 21 : 26*a + 22 : 1)
alice shared key: (20*a + 25 : 8*a + 38 : 1)


bob side ouput:
Sender: bob
Receiver: alice
No of generator: 1
Base Field: 43 and Degree: 2
Curve order: 1836
Generator: (31*a + 9 : 32*a : 1)
Elliptic Curve: Elliptic Curve defined by y^2 + (37*a+39)*x*y + (6*a+32)*y = x^3 + (a+41)*x^2 + (39*a+2)*x + (20*a+6) over Finite Field in a of size 43^2
bob Private Key: 1732
bob Public Key: (29*a + 20 : 42*a + 15 : 1)
bob shared key: (20*a + 25 : 8*a + 38 : 1)


Example 3:

Execution command on alice side: sage dh.py 3 3 0 0 0 0 a^2+a+2 2*a^2+a Alice bob
Execution command on bob side: sage dh.py 3 3 0 0 0 0 a^2+a+2 2*a^2+a bob Alice

Input 3:
Base_Field= 3
Degree= 3
Choice_of_coeff= 0
coeff_a1= 0
coeff_a2= 0
coeff_a3= 0
coeff_a4= a^2+a+2
coeff_a6= 2*a^2+a

participant_1= Alice
participant_2= bob

Alice side output:
Sender: Alice
Receiver: bob
No of generator: 1
Base Field: 3 and Degree: 3
Curve order: 37
Generator: (1 : 2*a^2 + a + 1 : 1)
Elliptic Curve: Elliptic Curve defined by y^2 = x^3 + (a^2+a+2)*x + (2*a^2+a) over Finite Field in a of size 3^3
Alice Private Key: 5
Alice Public Key: (2*a : 2*a^2 + 2*a + 2 : 1)
Alice shared key: (a + 2 : a^2 + a : 1)

bob side output:
Sender: bob
Receiver: Alice
No of generator: 1
Base Field: 3 and Degree: 3
Curve order: 37
Generator: (1 : 2*a^2 + a + 1 : 1)
Elliptic Curve: Elliptic Curve defined by y^2 = x^3 + (a^2+a+2)*x + (2*a^2+a) over Finite Field in a of size 3^3
bob Private Key: 31
bob Public Key: (a : 2*a^2 + 2 : 1)
bob shared key: (a + 2 : a^2 + a : 1)


Example 4:
Execution command on alice side: sage dh.py 9739 15 1 alice bob
Execution command on bob side: sage dh.py 9739 15 1 bob alice

Input 4:
Base_Field= 9739
Degree= 15
Choice_of_coeff= 1

Participant_1= alice
Participant_2= bob

alice side output:
Sender: alice
Receiver: bob
No of generator: 1
Base Field: 9739 and Degree: 15
Curve order: 672535924081209949272334954060291495202067658160856138659983
Generator: (2220*a^14 + 7150*a^13 + 2874*a^12 + 4533*a^11 + 4185*a^10 + 4580*a^9 + 8047*a^8 + 9249*a^7 + 7645*a^6 + 5081*a^5 + 2880*a^4 + 4411*a^3 + 6613*a^2 + 6502*a + 1709 : 4936*a^14 + 9310*a^13 + 1738*a^12 + 1054*a^11 + 5547*a^10 + 7866*a^9 + 1046*a^8 + 5109*a^7 + 5426*a^6 + 8654*a^5 + 132*a^4 + 4743*a^3 + 8032*a^2 + 1756*a + 6130 : 1)
Elliptic Curve: Elliptic Curve defined by y^2 + (367*a^14+6518*a^13+8936*a^12+6169*a^11+7852*a^10+2810*a^9+1425*a^8+1839*a^7+1721*a^6+6622*a^5+7575*a^4+9300*a^3+3469*a^2+2069*a+5184)*x*y + (1385*a^14+5667*a^13+1592*a^12+8928*a^11+5880*a^10+1880*a^9+5279*a^8+1986*a^7+4678*a^6+8409*a^5+8866*a^4+3167*a^3+8392*a^2+4730*a+1691)*y = x^3 + (8124*a^14+3243*a^13+3901*a^12+8087*a^11+4259*a^10+2534*a^9+6034*a^8+1130*a^7+1262*a^6+455*a^5+5144*a^4+6983*a^3+5191*a^2+2295*a+76)*x^2 + (3713*a^14+8319*a^13+7307*a^12+8992*a^11+142*a^10+4212*a^9+5448*a^8+663*a^7+802*a^6+7981*a^5+7563*a^4+8608*a^3+4536*a^2+2268*a+1709)*x + (2289*a^14+1655*a^13+4690*a^12+225*a^11+4644*a^10+7840*a^9+6466*a^8+7632*a^7+3845*a^6+7227*a^5+7443*a^4+2835*a^3+4064*a^2+7725*a+1331) over Finite Field in a of size 9739^15
alice Private Key: 546247132835485231957935516028912558525036127728221122789356
alice Public Key: (9481*a^14 + 8411*a^13 + 4365*a^12 + 3943*a^11 + 410*a^10 + 6128*a^9 + 9587*a^8 + 2322*a^7 + 8458*a^6 + 545*a^5 + 1308*a^4 + 1082*a^3 + 8747*a^2 + 7711*a + 4858 : 9615*a^14 + 3981*a^13 + 1868*a^12 + 2111*a^11 + 1219*a^10 + 3923*a^9 + 1613*a^8 + 7661*a^7 + 6669*a^6 + 1344*a^5 + 6347*a^4 + 8124*a^3 + 6724*a^2 + 17*a + 7889 : 1)
alice shared key: (6638*a^14 + 782*a^13 + 145*a^12 + 1257*a^11 + 3943*a^10 + 6296*a^9 + 1800*a^8 + 9211*a^7 + 6410*a^6 + 2429*a^5 + 904*a^4 + 1047*a^3 + 5529*a^2 + 1043*a + 4761 : 4929*a^14 + 6258*a^13 + 402*a^12 + 7592*a^11 + 138*a^10 + 9592*a^9 + 8993*a^8 + 1044*a^7 + 8214*a^6 + 8550*a^5 + 633*a^4 + 1736*a^3 + 755*a^2 + 1381*a + 3519 : 1)

bob side output:
Sender: bob
Receiver: alice
No of generator: 1
Base Field: 9739 and Degree: 15
Curve order: 672535924081209949272334954060291495202067658160856138659983
Generator: (2220*a^14 + 7150*a^13 + 2874*a^12 + 4533*a^11 + 4185*a^10 + 4580*a^9 + 8047*a^8 + 9249*a^7 + 7645*a^6 + 5081*a^5 + 2880*a^4 + 4411*a^3 + 6613*a^2 + 6502*a + 1709 : 4936*a^14 + 9310*a^13 + 1738*a^12 + 1054*a^11 + 5547*a^10 + 7866*a^9 + 1046*a^8 + 5109*a^7 + 5426*a^6 + 8654*a^5 + 132*a^4 + 4743*a^3 + 8032*a^2 + 1756*a + 6130 : 1)
Elliptic Curve: Elliptic Curve defined by y^2 + (367*a^14+6518*a^13+8936*a^12+6169*a^11+7852*a^10+2810*a^9+1425*a^8+1839*a^7+1721*a^6+6622*a^5+7575*a^4+9300*a^3+3469*a^2+2069*a+5184)*x*y + (1385*a^14+5667*a^13+1592*a^12+8928*a^11+5880*a^10+1880*a^9+5279*a^8+1986*a^7+4678*a^6+8409*a^5+8866*a^4+3167*a^3+8392*a^2+4730*a+1691)*y = x^3 + (8124*a^14+3243*a^13+3901*a^12+8087*a^11+4259*a^10+2534*a^9+6034*a^8+1130*a^7+1262*a^6+455*a^5+5144*a^4+6983*a^3+5191*a^2+2295*a+76)*x^2 + (3713*a^14+8319*a^13+7307*a^12+8992*a^11+142*a^10+4212*a^9+5448*a^8+663*a^7+802*a^6+7981*a^5+7563*a^4+8608*a^3+4536*a^2+2268*a+1709)*x + (2289*a^14+1655*a^13+4690*a^12+225*a^11+4644*a^10+7840*a^9+6466*a^8+7632*a^7+3845*a^6+7227*a^5+7443*a^4+2835*a^3+4064*a^2+7725*a+1331) over Finite Field in a of size 9739^15
bob Private Key: 200453523922267145491845324042937193688270050269540475576145
bob Public Key: (306*a^14 + 4652*a^13 + 5698*a^12 + 4898*a^11 + 8793*a^10 + 4967*a^9 + 781*a^8 + 2533*a^7 + 7459*a^6 + 5615*a^5 + 3455*a^4 + 4444*a^3 + 7716*a^2 + 9133*a + 2404 : 3424*a^14 + 1941*a^13 + 2190*a^12 + 7272*a^11 + 7013*a^10 + 7771*a^9 + 6101*a^8 + 3954*a^7 + 1316*a^6 + 5315*a^5 + 9201*a^4 + 676*a^3 + 6057*a^2 + 8632*a + 6913 : 1)
bob shared key: (6638*a^14 + 782*a^13 + 145*a^12 + 1257*a^11 + 3943*a^10 + 6296*a^9 + 1800*a^8 + 9211*a^7 + 6410*a^6 + 2429*a^5 + 904*a^4 + 1047*a^3 + 5529*a^2 + 1043*a + 4761 : 4929*a^14 + 6258*a^13 + 402*a^12 + 7592*a^11 + 138*a^10 + 9592*a^9 + 8993*a^8 + 1044*a^7 + 8214*a^6 + 8550*a^5 + 633*a^4 + 1736*a^3 + 755*a^2 + 1381*a + 3519 : 1)
'''


from sage.all import *
import sys
import os
import json
import random as pyrandom
import fcntl

def key_exchange_handler(base_field, degree, coeff, sender, receiver):

    ## generating the Field over the base_field and degree
    F= GF((base_field, degree), ('a',))

    ## generating the Elliptic Curve
    E= EllipticCurve(F, coeff)
    
    generator= E.gens()
    print(f'No of generator: {len(generator)}')
    
    if(len(generator)>1):
        remove_public_channel()
        raise ValueError("[-] More than 1 generator. Enter another set of coefficients !!")
    
    ## extracting the only generator available in the curve
    gen= generator[0]

    curve_order= E.order()
    print(f'Base Field: {base_field} and Degree: {degree}')
    print(f'Curve order: {curve_order}')
    print(f"Generator: {gen}")
    print(f"Elliptic Curve: {E}")
    
    ## creating the private key for the participant
    private_key= pyrandom.randint(2, curve_order-2)
    
    print(f"{sender} Private Key: {private_key}")

    ## creating the public key for the participant 
    public_key= private_key*gen

    print(f"{sender} Public Key: {public_key}")

    ## Extracting the x-coordinate and y-coordinate of the public key and creating the public-key message that the receiver will read. 
    x,y= public_key.xy()
    message={ 
        'type': "pubkey",
         'from': f'{sender}',
         'payload': {
            "x": str(x),
            "y": str(y)
         }
        
        }
    
    ## writing the public-key in the public channel
    with open('public.txt', 'a') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(message)+'\n')
        f.flush()
        os.fsync(f.fileno())
        fcntl.flock(f, fcntl.LOCK_UN)

    ## polling over the public channel to check if the public-key from receiver-end is available in the public channel
    while True:
        if os.path.exists(f'public.txt'):
            with open('public.txt', 'r') as f:
                fcntl.flock(f, fcntl.LOCK_SH)
               
                found_flag= False
                for item in f:
                    line= json.loads(item)
                    if line['type']=='pubkey' and line['from']==f'{receiver}' and line['payload'] is not None:
                        found_flag= True
                        break
                fcntl.flock(f, fcntl.LOCK_UN)

                if found_flag:
                    break


    ## reading the public-key of receiver from the public channel and updating the read_count
    with open(f'public.txt', 'r+') as f:
        fcntl.flock(f, fcntl.LOCK_EX)

        pub_payload= None
        for item in f:
            line= json.loads(item)
            if line['type']=='pubkey' and line['from']==f'{receiver}' and line['payload'] is not None:
                pub_payload= line['payload']
                break

        read_count= 0
        if pub_payload is not None:
            
            for line in f:
                line= json.loads(line)
                if line['type']=='read_count':
                    read_count= int(line['participant_read_count'])
                    read_count= read_count+1
                    break  
                                
            f.seek(0)
            f.write(json.dumps({
                "type": 'read_count',
                'participant_read_count': str(read_count)
            })+ '\n')

            f.flush()
            os.fsync(f.fileno())
        fcntl.flock(f, fcntl.LOCK_UN)

    ## recreating the receiver's public-key
    x, y= pub_payload['x'], pub_payload['y']
    receiver_pub_key= E(F(x), F(y))
    print(f"Received key: {receiver_pub_key} from {receiver}")
    
    ## generating the shared key using the receiver-public key and the private key created above
    shared_key= receiver_pub_key* private_key

    print(f"{sender}-{receiver} shared key: {shared_key}")


## this helps in cleaning up the residual files created (although only one file is created ie. the file mimicing the public channel)
def remove_public_channel():
    if os.path.exists("public.txt"):
        os.remove("public.txt")
        print('[+] Removed public.txt file')


def main():

    USAGE1= 'FORMAT1: sage dh.py <Base_Field> <Degree> <Choice_of_coeff(=0)> <Coeff_a1> <Coeff_a2> <Coeff_a3> <Coeff_a4> <Coeff_a6> <Sender_Name> <Receiver_Name>'
    USAGE2= 'FORMAT2: sage dh.py <Base_Field> <Degree> <Choice_of_coeff(=1) <Sender_Name> <Receiver_Name>'

    if(len(sys.argv)<4):
        print("[-] Not Enough Arguments !!")
        print('Follow either of the usages below:')
        print(USAGE1)
        print(f'\n{USAGE2}')
        exit(1)

    ## creates the public channel (as a file)
    if not os.path.exists("public.txt"):
        with open('public.txt', 'a') as f:
            msg= {
                'type': 'read_count',
                'participant_read_count': str(0),
            } 
            f.write(json.dumps(msg)+ '\n')


    ## reading the curve parameters from the CLI required for creating the Elliptic Curve
    base_field= int(sys.argv[1])

    degree= int(sys.argv[2])
    choice_of_coeff= int(sys.argv[3])    
    
    ## generating the field 
    try:
        F= GF((base_field, degree), names=('a',))
    except Exception as e:
        print(f'[-] Error in finite field creation: {e}')
        remove_public_channel()
        
    
    coeff= None
    sender, receiver= None, None

    ## Handling the case when choice_of_coeff==0
    if choice_of_coeff==0:
        if(len(sys.argv)!=11):
            print("[-] Not enough arguments")
            print('Follow the usage below:')
            print(USAGE1)
            remove_public_channel()
            exit(1)

        ## reading the sender and receiver party name from CLI
        sender= sys.argv[9]
        receiver= sys.argv[10]
        
        ## handling the case when degree==1
        if degree==1:
            coeff_a1= int(sys.argv[4])
            coeff_a2= int(sys.argv[5])
            coeff_a3= int(sys.argv[6])
            coeff_a4= int(sys.argv[7])
            coeff_a6= int(sys.argv[8])
        
        ## handling the case when degree>1
        elif degree>1:
            coeff_a1= F(sys.argv[4])
            coeff_a2= F(sys.argv[5])
            coeff_a3= F(sys.argv[6])
            coeff_a4= F(sys.argv[7])
            coeff_a6= F(sys.argv[8])
            
        coeff= [coeff_a1, coeff_a2, coeff_a3, coeff_a4, coeff_a6]


        ## writing over the curve parameters alongwith the curve coefficients in the public channel
        with open('public.txt', 'w') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            
            f.write(
                json.dumps(
                    {
                        "type": "coeff",
                        "base_field": str(base_field),
                        "degree": str(degree),
                        "choice_of_coeff": str(choice_of_coeff),
                        "payload": [str(item) for item in coeff]
                    }
                )+ '\n'
            )

            f.flush()
            os.fsync(f.fileno())

            print('[+] Added the coeff to public.txt')
        fcntl.flock(f, fcntl.LOCK_UN)

    ## handling the case when choice_of_coeff==1 (need to use random coefficients generated by the curve)
    elif choice_of_coeff==1:

        if len(sys.argv)!=6:
            print('[-] Only 5 arguments are allowed')
            print('Follow the usage below:')
            print(USAGE2)
            remove_public_channel()
            exit(1)

        sender= sys.argv[4]
        receiver= sys.argv[5]

        ## checking if curve coefficients are available then reading them else generating the curve coefficients and writing them over to the public channel
        with open("public.txt", 'r+') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            data_flag= True
            for item in f:
                line= json.loads(item)
                if line['type']=='coeff' and line['payload'] is not None:
                    data_flag= False
                    coeff= []
                    for element in line['payload']:
                        coeff.append(F(element))
                    
                    break

            if data_flag:
                coeff_a1= F.random_element()
                coeff_a2= F.random_element()
                coeff_a3= F.random_element()
                coeff_a4= F.random_element()
                coeff_a6= F.random_element()
                coeff= [coeff_a1, coeff_a2, coeff_a3, coeff_a4, coeff_a6]
                
                cf= [str(c) for c in coeff]
                f.write(json.dumps(
                    {"type": "coeff",
                     "base_field": str(base_field),
                     "degree": str(degree),
                     "choice_of_coeff": str(choice_of_coeff),
                    "payload": cf
                    }
                )+'\n')
                
                f.flush()
                os.fsync(f.fileno())

                print(f'[+] Generated new random coefficients and appended to public.txt')
            fcntl.flock(f, fcntl.LOCK_UN)
    
    print(f"Sender: {sender}")
    print(f"Receiver: {receiver}")

    ## calling over the function that is handling the key exchange
    try:
        key_exchange_handler(base_field, degree, coeff, sender, receiver)
    
    except Exception as e:
        print(e)
    
    '''
    Open channel cleanup process; Currently archived.

    finally:
        print("Inside finally block")
        if os.path.exists(f"public.txt"):
            completion_flag= False
            try:
                time.sleep(1)
                with open("public.txt", 'r') as f:
                    fcntl.flock(f, fcntl.LOCK_SH)
                    for item in f:
                        line= json.loads(item)
                        if line['type']=='read_count' and (line['participant_read_count'])==str(2):
                            
                            completion_flag=True
                            break
                    fcntl.flock(f, fcntl.LOCK_UN)
                
                if completion_flag:            
                    os.remove(f"public.txt")
                    print("[+] Removed public.txt as both participants have read the public keys.")
            
            except Exception:
                print(f"File does not exist to remove")
    '''
if __name__=="__main__":
    main()
