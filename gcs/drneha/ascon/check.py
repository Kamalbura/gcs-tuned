from ascon import *
import time

start = time.time()

debug = False
debugpermutation = False

variant='Ascon-128'
key_size=16
key   = get_random_bytes(key_size)
nonce   = get_random_bytes(16)
ad = b"ANY RANDOM DATA"

m1=b'Hi I am Debrup'
m2=b' Chatterjee. '


c1 = ascon_encrypt(key, nonce, ad, m1,  variant)
c2 = ascon_encrypt(key, nonce, ad, m2,  variant)
print(c1,end='\n')
print(c2,end='\n')
print(c1+c2,end='\n')

m3=m1+m2
print(m3,end='\n')

c3=ascon_encrypt(key, nonce, ad, m3,  variant)
print(c3,end='\n')

print(m1+m2==m3, end='\n')