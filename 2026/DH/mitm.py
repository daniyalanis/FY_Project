'''
About:
This script simulate MITM (Man-In-The-Middle) attack between Alice and Bob who participate for Diffie-Hellman Key Exchange using Elliptic Curve. 
It polls over the public channel for key sharing by participating party and if available reads the actual key and provide the forged key for each of the participants.   


USAGE_FORMAT: sage mitm.py <participant1 name> <participant2 name> <attacker name>

NOTE: The provision for cleanp has been removed and thus, manual intervention is needed to cleanup the txt file. 

'''

from sage.all import *
import sys
import os
import json
import random as pyrandom
import fcntl

## reads curve parameters and coefficients. 
def read_coeff():
    
    with open('public.txt', 'r') as f:
        fcntl.flock(f, fcntl.LOCK_SH)
        
        base_field, degree, choice_of_coeff= None, None, None
        cf= None
        coeff= None

        data_flag= False
        for item in f:
            line= json.loads(item)
            if line['type']=='coeff':
                base_field= int(line['base_field'])
                degree= int(line['degree'])
                choice_of_coeff= int(line['choice_of_coeff'])
                cf= line['payload']

                data_flag= True
                break
        fcntl.flock(f, fcntl.LOCK_UN)

    if data_flag:
        print(f'base_field: {base_field}')
        print(f'Degree: {degree}')
        F= GF((base_field, degree), ('a',))
        
        if choice_of_coeff==0 and degree==1:
            coeff= [int(item) for item in cf]

        else:
            coeff= [F(c) for c in cf]

    if coeff is not None:
        return base_field, degree, F, coeff
    else:
        return None, None, None, None

## this function generates private-key and public-key 
def get_private_public_key(gen, curve_order):
    private_key= pyrandom.randint(2, curve_order-2)
    public_key= private_key*gen

    return private_key, public_key

## This function reads the public channel and finds key from one of the participants and modify the key read for duping the other party too. 
def read_and_modify(F, E, attacker_public_key, sender, receiver):
    
    with open(f'public.txt', 'r+') as f:
        fcntl.flock(f, fcntl.LOCK_EX)

        participant= None
        x_payload, y_payload= None, None
        line_number= None
        lines= f.readlines()
        for line_no, item in enumerate(lines):
            msg= json.loads(item)
            if msg['type']=='pubkey' and msg['from'] in [sender, receiver]: ## read key from either of participants
                participant= msg['from']
                x_payload, y_payload= msg['payload']['x'], msg['payload']['y'] 
                line_number= line_no
                
                break

        x,y= attacker_public_key.xy()
        #print(f"inside read_and_modify and writing forged key to be read by {participant}")
        forged_msg_read_by_participant= {
            'type': 'pubkey',
            'from': sender if participant!=sender else receiver,
            'payload': {
                'x': str(x),
                'y': str(y)
            }
        }
        
        modified_msg_read_by_another_participant= {
            'type': 'pubkey',
            'from': participant,
            'payload': {
                'x': str(x),
                'y': str(y)
            }}
        
        lines.append(json.dumps(forged_msg_read_by_participant)+ '\n')
        if line_number is not None:
            lines[line_number]= json.dumps(modified_msg_read_by_another_participant)+ '\n'
        
        f.seek(0)
        f.writelines(lines)
        f.truncate()
        f.flush()
        os.fsync(f.fileno())
        
        fcntl.flock(f, fcntl.LOCK_UN)
        return E(F(x_payload), F(y_payload)), participant

## this reads the second participant's public-key
def read_target(E, F, participant):

    while True:
        flag= False
        with open(f'public.txt', 'r') as f:
            fcntl.flock(f, fcntl.LOCK_SH)

            public_key= None
            for item in f:
                line= json.loads(item)
                if line['type']== 'pubkey' and line['from']==participant and line['payload'] is not None:
                    flag=True
                    public_key= E(F(line['payload']['x']), F(line['payload']['y']))
                    break
        
            fcntl.flock(f, fcntl.LOCK_UN)
            '''
            if flag==False:
                time.sleep(0.5)
            '''
            if flag:
                return public_key, participant


## probe to check which participant's key increases read_count to remove forged key 
def probe_read_count(participant):
    
    with open('public.txt', 'r+') as f:
        fcntl.flock(f, fcntl.LOCK_EX)

        lines= f.readlines()
        kept_lines= []

        for line in lines:
            msg= json.loads(line)
            if msg['type']=='pubkey' and msg['from']==participant:
                continue
            else:
                kept_lines.append(line)
        f.seek(0)
        f.writelines(kept_lines)
        f.truncate()
        f.flush()
        os.fsync(f.fileno())
        fcntl.flock(f, fcntl.LOCK_UN)

## this checks if both public key available; if available then assume that the exchange has already happened and no need to perform any attack !!
def check_both_pubkey(sender, receiver):
    participant1_present= False
    participant2_present= False

    with open('public.txt', 'r') as f:
        fcntl.flock(f, fcntl.LOCK_SH)

        for item in f:
            msg= json.loads(item)
            if msg['type']=='pubkey' and msg['from']==sender:
                participant1_present=True
            
            elif msg['type']=='pubkey' and msg['from']==receiver:
                participant2_present= True
            
            if participant1_present and participant2_present:
                break

        fcntl.flock(f, fcntl.LOCK_UN)

    return participant1_present and participant2_present

## main script for handling the attack
def mitm_attack(base_field, degree, F, coeff, sender, receiver, attacker):
    E= EllipticCurve(F, coeff)

    generator= E.gens()
    print(f"No of generator: {len(generator)}")

    if len(generator)>1:
        raise ValueError('[-] More than 1 generator. Enter another set of coefficients !!')

    gen= generator[0]
    curve_order= E.order()

    print(f'Base Field: {base_field} and Degree: {degree}')
    print(f"Curve order: {curve_order}")
    print(f'Generator: {gen}')
    print(f"Elliptic Curve: {E}")

    attacker_private_key, attacker_public_key= get_private_public_key(gen, curve_order)
    
    print(f"[+] {attacker} private key: {attacker_private_key}")
    print(f"[+] {attacker} public key: {attacker_public_key}")
    
    ## keep waiting until public.txt file available
    print('[+] Waiting for public.txt if not created already...')
    while os.path.exists('public.txt')==False:
        continue

    ## check if both parties public key available then exit
    if check_both_pubkey(sender, receiver):
        print('[+] Both participants public keys are already present. Possibly exchange happened already. Aborting...')
        exit(1)


    pubkey1, participant1= read_and_modify(F, E, attacker_public_key, sender, receiver)

    print(f"Got the key: {pubkey1} from {participant1}")
    p2= sender if participant1!=sender else receiver

    ## probe to check which participant's key increases read_count to remove forged key
    probe_read_count(p2)
    
    pubkey2, participant2= read_target(E, F, p2)
    print(f"Got the key: {pubkey2} from {participant2}")

    sender_shared_key= pubkey1*attacker_private_key
    receiver_shared_key= pubkey2*attacker_private_key

    print(f'[+] {attacker}-{participant1} shared key: {sender_shared_key}')
    print(f'[+] {attacker}-{participant2} shared key: {receiver_shared_key}')


def main():
    USAGE_FORMAT= 'sage mitm.py <participant1 name> <participant2 name> <attacker name>'
    if len(sys.argv)<4:
        print(f'Not enough arguments')
        print(f'Follow: {USAGE_FORMAT}')

        exit(1)
    
    base_field, degree,F, coeff= None, None, None, None
    
    sender= sys.argv[1]
    receiver= sys.argv[2]
    attacker= sys.argv[3]
    
    print(f'[+] Waiting for either {sender} or {receiver}, to get the Elliptic Curve parameters...')

    while os.path.exists('public.txt')==False:
        continue

    while True:
        base_field, degree, F, coeff= read_coeff()
        if coeff is not None:
            print('[+] Curve parameters and Coefficients received...')
            break
    

    mitm_attack(base_field, degree, F, coeff, sender, receiver, attacker)

if __name__=='__main__':
    
    try:

        main()
    except Exception as e:
        print(e)
    '''
    except Exception as e:
        print(e)
    '''
    '''
    finally:
        if os.path.exists(f"public.txt"):
            completion_flag= False
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
    '''
