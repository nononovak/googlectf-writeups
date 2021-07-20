#!/usr/bin/env python3

import string
import binascii
import socket
import base64
import itertools
import os
import time

from collide_gcm_sage import multi_collide_gcm

def log(str):
	t = time.strftime("%H:%M:%S", time.localtime())
	print(f'{t} {str}')

def derive_key(pw):
	from cryptography.hazmat.backends import default_backend
	from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
	kdf = Scrypt(salt=b'', length=16, n=2**4, r=8, p=1, backend=default_backend())
	key = kdf.derive(pw.encode())
	return key

CIPHERTEXTS = {}
def create_partition_ct(keyset):
	global CIPHERTEXTS
	hash_key = ','.join(binascii.hexlify(k).decode() for k in keyset)
	if hash_key in CIPHERTEXTS:
		return CIPHERTEXTS[hash_key]
	log(f'[+] Generating partition for {len(keyset)} ciphertexts')
	nonce = b'\x00'*12
	tag = b'\x01'*16
	ct = multi_collide_gcm(keyset, nonce, tag)
	if len(keyset) > 300: # anything less is not computationally expensive
		CIPHERTEXTS[hash_key] = ct
		save_partitions()
	return ct

def save_partitions(filename='partitions.txt'):
	global CIPHERTEXTS
	log(f'[+] Saving {len(CIPHERTEXTS)} generated ciphertexts')
	with open(filename,'w') as fhandle:
		for hash_key in CIPHERTEXTS:
			ct = binascii.hexlify(CIPHERTEXTS[hash_key]).decode()
			fhandle.write(ct+','+hash_key+'\n')
		fhandle.close()

def read_partitions(filename='partitions.txt'):
	global CIPHERTEXTS
	if not os.path.exists(filename):
		return
	with open(filename,'r') as fhandle:
		for line in fhandle:
			elems = line.strip().split(',')
			hash_key = ','.join(elems[1:])
			CIPHERTEXTS[hash_key] = binascii.unhexlify(elems[0])
		fhandle.close()
	log(f'[+] Loaded {len(CIPHERTEXTS)} generated ciphertexts')

def readuntil(s,buf):
	res = s.recv(1024)
	while not res.endswith(buf):
		res = res + s.recv(1024)
	return res

def setkey(s,idx):
	s.send(b'1\n')
	readuntil(s,b'>>> ')
	s.send(b'%d\n' % idx)
	readuntil(s,b'>>> ')

def readflag(s,pw):
	s.send(b'2\n')
	readuntil(s,b'>>> ')
	s.send(pw.encode() + b'\n')
	resp = readuntil(s,b'>>> ').decode()
	log(f'[*] Flag response: {resp}')

def decryptext(s,ct):
	s.send(b'3\n')
	readuntil(s,b'>>> ')
	nonce=b'\x00'*12
	value = base64.b64encode(nonce) + b',' + base64.b64encode(ct) + b'\n'
	s.send(value)
	res = b'Decryption successful' in readuntil(s,b'>>> ')
	return res

def solve_key(s,keyid,N=16):

	setkey(s,keyid)
	for index in range(N):
		candidates = ALL_KEYS[index::N]
		ct = create_partition_ct(candidates)
		res = decryptext(s,ct)
		log(f'[+] Partition {index}/{N} .. {res}')
		if res:
			break

	while len(candidates) > 1:
		ct = create_partition_ct(candidates[::2])
		res = decryptext(s,ct)
		log(f'[+] Splitting {len(candidates)} candidates .. {res}')
		if res:
			candidates = candidates[::2]
		else:
			candidates = candidates[1::2]

	pw = ALL_PASSWORDS[ALL_KEYS.index(candidates[0])]
	log(f'[*] Single key remaining {candidates} .. password == {pw}')
	return pw

def precompute_partitions(N=16):
	# N=4  ~12 minutes
	# N=8  ~3.5 minutes
	# N=16 ~45 seconds
	# N=32 ~15 seconds
	# N=64 ~3 seconds
	while N <= 32:
		for i in range(N):
			log(f'[+] Creating partition {i}/{N}')
			create_partition_ct(ALL_KEYS[i::N])
		N *= 2

if __name__ == '__main__':
	ALL_PASSWORDS = list(''.join(x) for x in itertools.product(string.ascii_lowercase,repeat=3))
	ALL_KEYS = [derive_key(pw) for pw in ALL_PASSWORDS]

	read_partitions()
	# optional
	precompute_partitions()

	server = ('pythia.2021.ctfcompetition.com',1337)
	log(f'[+] Connecting to {server}')
	s = socket.socket()
	s.connect(server)
	readuntil(s,b'>>> ')
	pw1 = solve_key(s,0)
	pw2 = solve_key(s,1)
	pw3 = solve_key(s,2)
	readflag(s,pw1+pw2+pw3)

	save_partitions()
