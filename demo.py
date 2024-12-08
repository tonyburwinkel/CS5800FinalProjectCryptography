import random, hashlib, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

headers = {
    'demo':'''
###################
# ENCRYPTION DEMO #
###################
''',
    'rsa_key_gen':'''
###############
# RSA KEY GEN # 
###############
''',
    'encrypt_&_sign':'''
####################
# ENCRYPT AND SIGN # 
####################
    ''',
    'dh':'''
##################
# DIFFIE HELLMAN # 
##################
''',
    'kx':'''
################
# KEY EXCHANGE #
################
''',
    'decrypt':'''
###########
# DECRYPT #
###########
''',
    'authenticate': '''
################
# AUTHENTICATE # 
################
''',
    'sending':'''
###########
# SENDING # 
###########
'''                                  
}

def prompt():
    prompt = input("Press [enter] to continue.\n")

######################
# Eratosthenes Sieve #
######################

def sieve(cap):
    prime = set()
    seive = [True] * cap
    seive[0] = False
    seive[1] = False
    for i in range(2, cap):
        for j in range(i * 2, cap, i):
            seive[j] = False

    # Filling the prime numbers
    for i in range(len(seive)):
        if seive[i]:
            prime.add(i)

    return list(prime)

#################
# RSA Functions #
#################

# Euclid's GCD algorithm
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Euclid's modular inverse algorithm for deriving private key
def mod_inverse(e, phi):
    t, new_t = 0, 1
    r, new_r = phi, e
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    if r > 1:
        raise ValueError("e is not invertible")
    if t < 0:
        t += phi
    return t

# take a hashed message digest and encrypt it using caller's RSA private key
# return the caller's digital signature
def signature(hash, d, n):
    return pow(hash, d, n) # hash^d%n

# take a hashed message digest and a public key and return the resulting signature verification
def authenticate(signature, e, n):
    return pow(signature, e, n) # verified digest should be equal to the digest hash signature^e%n

############################
# Diffie Hellman Functions #
############################

# raise the public generator to the sender's private exponent
# and feed it through the public modulus
def get_dh_pub(generator, modulus, priv):
    return (generator**priv)%modulus

# take a sender's public modular congruence and raise it 
# to the recipient's private exponent mod the public modulus
# returning the shared secret number
def get_dh_secret(modulus, pub, priv):
    return (pub**priv)%modulus

# Key Derivation Function (KDF)
# take the shared secret number, hash it using SHA-256, and generate
# an AES-128 symmetric encryption key by truncating the hash
# to 16 bytes or 128 bits
def get_session_key(secret):
    # convert the shared secret into a valid encryption key by hashing (simple way to do this, not secure)
    S_bytes = secret.to_bytes((secret.bit_length() + 7) // 8, byteorder='big')

    hash_output = hashlib.sha256(S_bytes).digest()  # Produces 256-bit hash
    key = hash_output[:16]  # Truncate to 16 bytes (128 bits) for AES-128

    return key

#######################################
# Hashing, Encryption, and Decryption #
#######################################

# encrypt a plaintext using the AES-128 session key
# using python's cryptography library
def encrypt_message(plaintext, key):
    if not isinstance(plaintext, bytes):
        plaintext = plaintext.encode('utf-8')  # Convert string to bytes
    
    iv = os.urandom(16)  # Generate a random 16-byte initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return {"iv":iv, "ciphertext":ciphertext}

# decrypt a ciphertext given the session key using python's cryptography library
def decrypt_message(iv, ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message.decode('utf-8')  # Convert bytes back to string

# Hash must be smaller than n
# Hashes message using SHA-256 and returns the hash as an integer for signing
def get_message_digest(message, n):
    if not isinstance(message, bytes):
        message = message.encode('utf-8')
    hash_bytes = hashlib.sha256(message).digest()
    hash_int = int.from_bytes(hash_bytes, byteorder='big')  # Convert hash to an integer
    return hash_int % n

#################
# DEMONSTRATION #
#################

def main():
    print(headers['demo'])
    print(f'''
    Demonstration Sections:
          
          1. Sieve of Eratosthenes: dynamic programming solution to generate prime numbers
          2. RSA key generation: creating public and private asymmetric encryption keys
          3. Diffie Hellman Key Exchange: Arriving at a shared secret symmetric encryption key
          4. Message encryption: Making a ciphertext from a plaintext to transmit 
          5. Message hashing: Creating a fixed length digest from your message
          6. Message signing: Using your RSA Private Key to encrypt the message digest
          7. Message transmission: Alice and Bob exchange encrypted messages and signatures
          8. Message decryption: decrypt the receied ciphertext using the shared symmetric encryption key
          9. Message authentication: Hash the decrypted message, decrypt the received signature, and compare the results
    
        ''')
    # Create a list of primes to choose from
    primes = sieve(1000000)

    print(f"Filling Sieve of Eratosthenes with primes up to 1000000...")

    prompt()

    # 2 people, Alice and Bob, and their cryptographic details
    alice = {
        "name":"Alice", 
        "message":"Meet me at midnight by the old oak tree.",
        "received":{},
        "digest":"",
        "signature":0,
        "cipher":"",
        "dhpriv": 0, 
        "dhpub":0, 
        "dhsecret": 0, 
        "dh_session_key": 0,
        "rsaprimes":[], 
        "rsaphi":0,
        "rsa_n":0,
        "rsa_d":0
        }
    
    bob = {
        "name":"Bob", 
        "message":"The eagle has landed.",
        "received":{},
        "signature":"",
        "hashed_digest":0,
        "cipher":"",
        "dhpriv": 0, 
        "dhpub":0, 
        "dhsecret": 0, 
        "dh_session_key": 0,
        "rsaprimes":[],
        "rsaphi":0,
        "rsa_n":0,
        "rsa_d":0 
        }
    
    print('Initiating demonstration...\n')

    ####################
    # RSA KEY CREATION #
    ####################

    print(headers['rsa_key_gen'])
    print('Initiating RSA key creation...\n')
    prompt()

    # typical rsa exponent (does not need to be randomly chosen)
    rsa_e = 65537

    # Alice and Bob establish RSA keys by first choosing 2 primes
    for i in range(2):
        alice['rsaprimes'].append(random.choice(primes))
        bob['rsaprimes'].append(random.choice(primes))

    # generate RSA keys
    for person in [alice, bob]:
        person['rsa_n'] = person['rsaprimes'][0]*person['rsaprimes'][1]
        print(f"{person['name']} chose primes p:{person['rsaprimes'][0]} and q:{person['rsaprimes'][1]}, and finds their product, p*q=n:\n")
        print(f"\t{person['rsa_n']} \n\nThis n along with the public exponent e (65537) constitutes their public key.\n")
        person['rsaphi'] = (person['rsaprimes'][0]-1)*(person['rsaprimes'][1]-1)
        print(f"Next, {person['name']} finds phi n. Since p and q were prime, phi n is just (p-1)(q-1):\n\n\t{person['rsaphi']}\n")
        print(f"Now {person['name']} must find the modular inverse of phi to establish their private key.")
        person['rsa_d'] = mod_inverse(rsa_e, person['rsaphi'])
        print(f"{person['name']} derived the modular inverse of phi n: \n\n\t{person['rsa_d']} \n\nThis, along with n, constitutes their private key.\n")
        print(f"\t{person['name']}'s RSA Public Key (n, e): ({person['rsa_n']}, {rsa_e})")
        print(f"\t{person['name']}'s RSA Private Key (n, d): ({person['rsa_n']}, {person['rsa_d']})\n")
        prompt()
        
    print(f"Alice and Bob post their public keys where anyone who wants to send them a message can find them.\n")
    prompt()

    ###############################
    # DIFFIE HELLMAN KEY EXCHANGE #
    ###############################

    print(headers['dh'])
    print(headers['kx'])

    # generator does not matter for security of DH
    # choosing 2 or 3 provides a modest performance benefit
    dh_gen = 3

    # choose a random prime modulus
    dh_mod = random.choice(primes)

    # Alice and Bob each choose a private exponent
    alice["dhpriv"] = random.randint(1, 1000)
    bob["dhpriv"] = random.randint(1, 1000)
    
    print(f"Initiating Diffie Hellman Key Exchange...\n")
    prompt()
    print(f"Alice and Bob agree on a public generator and modulus:")
    print(f"\tPublic generator: {dh_gen} \n\tPublic modulus: {dh_mod}\n")
    prompt()

    for person in [alice, bob]:
        print(f"{person['name']} chooses {person['dhpriv']} as their private exponent.")
        person['dhpub'] = get_dh_pub(dh_gen, dh_mod, person['dhpriv'])
        print(f"They derive {person['dhpub']} using the modulus and generator and send it over the channel.\n")
        prompt()

    alice['dhsecret'] = get_dh_secret(dh_mod, bob.get("dhpub"), alice.get("dhpriv"))
    bob['dhsecret'] = get_dh_secret(dh_mod, alice.get("dhpub"), bob.get("dhpriv"))

    print(f"Alice raises Bob's public number ({bob['dhpub']}) to their secret exponent ({alice['dhpriv']}) mod {dh_mod} to derive the shared secret:\n")
    print(f"\t{bob['dhpub']} ^ {alice['dhpriv']} % {dh_mod} = {alice['dhsecret']}\n")
    print(f"Bob raises Alice's public number ({alice['dhpub']}) to their secret exponent ({bob['dhpriv']}) mod {dh_mod} to derive the shared secret:\n")
    print(f"\t{alice['dhpub']} ^ {bob['dhpriv']} % {dh_mod} = {bob['dhsecret']}")

    prompt()
    
    for person in [alice, bob]:
        person['dh_session_key'] = get_session_key(person['dhsecret'])
        print(f"{person['name']} used the shared secret to derive the symmetric AES-128 session key: \n\t{person['dh_session_key']}\n")

    prompt()

    ##################################
    # MESSAGE ENCRYPTION AND SIGNING #
    ##################################

    print(headers['encrypt_&_sign'])

    print("Initiating message encryption and signing...")
    prompt()

    # hash the message
    # sign the hash
    for person in [alice, bob]:
        person['cipher'] = encrypt_message(person['message'], person['dh_session_key'])
        print(f"{person['name']} encrypts their message using the session key to produce the ciphertext:\n")
        print(f"\tMessage: \n\t\t{person['message']}\n")
        print(f"\tCiphertext: \n\t\t{person['cipher']['ciphertext']}\n")
        person['digest'] = get_message_digest(person['message'], person['rsa_n'])
        print(f"Now {person['name']} hashes their message using SHA-256 to get the digest: \n\n\t{person['digest']}\n")
        person['signature'] = signature(person['digest'], person['rsa_d'], person['rsa_n']) 
        print(f"Finally, {person['name']} encrypts the hashed digest h using their RSA private key n, d (h^d%n) to create this signature: \n\n\t{person['signature']}\n")
        person['sent'] = {
            "iv":person['cipher']['iv'],
            "ciphertext":person['cipher']['ciphertext'],
            "signature":person['signature'],
            "rsa_n":person['rsa_n']
        }

        prompt()

    ########################
    # MESSAGE TRANSMISSION #
    ########################

    print(headers['sending'])
    # send the message, the hash, and the initialization vector

    print('Now that Bob and Alice have encrypted and signed their messages, they exchange them...\n')

    prompt()


    for person in [alice, bob]:
        print(f"{person['name']}:\n\n\tciphertext:{person['cipher']['ciphertext']}\n\n\tsignature:{person['signature']}\n")
        print('Message transmitted...')
        prompt()

    alice['received'] = bob['sent']
    bob['received'] = alice['sent']

    #########################################
    # MESSAGE DECRYPTION AND AUTHENTICATION # 
    #########################################

    print(headers['decrypt'])

    # have the recipient decrypt the message and show the plaintext

    for person in [alice, bob]:
        iv = person['received']['iv']
        ct = person['received']['ciphertext']
        sig = person['received']['signature']
        n = person['received']['rsa_n']
        
        decrypted = decrypt_message(iv, ct, person['dh_session_key'])
        print(f"{person['name']} used the symmetric AES-128 session key to decrypt this message:\n\t{decrypted}.\n")
        person['received']['decrypted'] = decrypted
        prompt()

        print(headers['authenticate'])
        # have the recipient hash the plaintext
        
        digest = get_message_digest(decrypted, n)
        print(f"{person['name']} hashed the message using SHA-256 and got this digest:\n\n\t{digest}\n")
        person['received']['digest'] = digest
        prompt()

        # have the recipient decrypt the signature
        # have the recipient compare their message digest to the decrypted signature

        auth = authenticate(sig, rsa_e, n)
        person['received']['authentication'] = auth
        print(f"{person['name']} decrypted the signature s they got with the message using the sender's public key n, e (s^e%n) to get this hash:")
        print(f"\n\t{sig} ^ {rsa_e} % {n} = {auth}\n")
        if auth == digest:
            print(f"Signature matches the digest, message is authentic.")
        prompt()

if __name__ == "__main__":
    main()