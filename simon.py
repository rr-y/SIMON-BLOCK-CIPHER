from collections import deque
import sys
import binascii
mod = 2**16 -1

z = [0b01100111000011010100100010111110110011100001101010010001011111,
0b01011010000110010011111011100010101101000011001001111101110001,
0b11001101101001111110001000010100011001001011000000111011110101,
0b11110000101100111001010001001000000111101001100011010111011011,
0b11110111001001010011000011101000000100011011010110011110001011]
def encryption(planetext,n,key_schedule):
	#mod = (2**n) - 1
	b = (planetext >> n) & mod
	a = (planetext & mod)
	b , a = encryption_function(n,b,a,key_schedule)
	return (b << n) + a


def encryption_function(n,x,y,key_schedule):
	#mod = (2**n)-1
	for k in key_schedule:
		s1=((x >> n-1) + (x << 1)) & mod
		s2=((x >> n-2) + (x << 2)) & mod
		s8=((x >> n-8) + (x << 8)) & mod
		xor_1 = (s1 & s8) ^ y
		xor_2 = xor_1 ^ s2
		y = x
		x = k ^ xor_2
	return x ,y

def decryption(ciphertext,n,key_schedule):
	 b = (ciphertext >> n ) & mod
	 a = ciphertext & mod

	 a, b = decrypt_function(n,a,b,key_schedule)
	 return (b << n ) + a


def decrypt_function(n ,x ,y ,key_schedule):

	for k in reversed(key_schedule):
		s1=((x >> n-1) + (x << 1)) & mod
		s2=((x >> n-2) + (x << 2)) & mod
		s8=((x >> n-8) + (x << 8)) & mod
		xor_1 = (s1 & s8) ^ y
		xor_2 = xor_1 ^ s2
		y = x
		x = k ^ xor_2
	return x ,y

#Wordsize
n = 16

# keywords
m = 4

# NO ofrounds 
T = 32

#Plaintext to encrypt
planetext= input("PLANETEXT: ")
planetext= planetext.encode('utf-8')
planetext= int(planetext.hex(),16)



#Key for encryption of plain text
key = input("KEY: ")
key = key.encode('utf-8')
key = int(key.hex(),16)

# Parse the given key and truncate it to the key length
key = key & ((2 ** 64) - 1)



key_schedule = []
 #sub key-words

k_m =  [((key >> (n * ((m-1) - x))) & (2**n - 1)) for x in range(m)]

print("KEY-WORDS")
print(k_m)

#Round constant #0xFFFFF...c
c = (2**n -1) ^ 3

#using deque to manage subwords
k_reg = deque(k_m)

#Generate all round keys
for x in range(T):
	rs_3 = ((k_reg[0] << (n - 3)) + (k_reg[0] >> 3)) & mod
	if m == 4:
		rs_3 = rs_3 ^ k_reg[2]
	rs_1 = ((rs_3 << (n - 1)) + (rs_3 >> 1)) & mod

	c_z = ((z[0] >> (x % 62)) & 1) ^ c

	new_k = c_z ^ rs_1 ^ rs_3 ^ k_reg[m - 1]
	key_schedule.append(k_reg.pop())
	k_reg.appendleft(new_k)

#Printing all round key
print("SUB-ROUND KEYS: ")
print(key_schedule)
print()

print("ENCRYPTED CIPHERTEXT: ")
hex1=hex((encryption(planetext,n,key_schedule)))
print(hex1)


print("DECRYPTED CIPHERTEXT: ")
hex2=hex(decryption(encryption(planetext,n,key_schedule),n,key_schedule))
hex2=binascii.unhexlify(hex2[2:])
print(hex2.decode())




