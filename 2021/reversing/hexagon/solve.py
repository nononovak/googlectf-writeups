#!/usr/bin/env python3

import binascii
import struct

def hex1(R0,R1):
	if R1 & 1<<6:
		R5 = 2046968324 # 0x7a024204
		R0 = R0 + R5
		R0 = -1-R0
	else:
		####
		R5 = 173879092 # 0xa5d2f34
		R0 = R0 + R5
		R0 = -1-R0
	return R0

def hex2(R0,R1):
	if R1 & 1<<3:
		R5 = -420194037 # 0xe6f4590b
		R0 = R0 ^ R5
		R5 = 1418186270 # 0x5487ce1e
		R0 = R0 + R5
	else:
		#####
		R0 = -1-R0
		R5 = 1210484339 # 0x48268673
		R0 = R0 ^ R5
	return R0

def hex3(R0,R1):
	if R1 & 1<<8:
		R5 = -2055770470
		R0 = R0 + R5
	else:
		#####
		R5 = 1519522183
		R0 = R0 ^ R5
		R5 = -373614660
		R0 = R0 + R5
	return R0

def hex4(R0,R1):
	if R1 & 1<<0:
		R0 = -1-R0
		R0 = -1-R0
	else:
		#####
		R0 = -1-R0
		R5 = -686802991
		R0 = R0 ^ R5
	return R0

def hex5(R0,R1):
	if R1 & 1<<0:
		#####
		R0 = -1-R0
		R5 = 270515404
		R0 = R0 + R5
	else:
		R0 = -1-R0
		R5 = 1430804514
		R0 = R0 + R5
	return R0

def hex6(R0,R1):
	if R1 & 1<<3:
		R5 = 1235478542 # 0x49a3e80e
		R0 = R0 ^ R5
		R5 = 1653137829 # 0x6288e1a5
		R0 = R0 ^ R5
	else:
		#####
		R5 = -1962843199 # 0x8b0163c1
		R0 = R0 ^ R5
		R5 = -288476533 # 0xeece328b
		R0 = R0 ^ R5
	return R0

def check_flag(target):
	# '* google binja-hexagon *'
	R2,R3 = struct.unpack('II',b'AAAABBBB')
	R0 = 1869029418 # 0x6f67202a '* go'
	R0,R2 = R2,R0
	R1 = 1
	R0 = hex1(R0,R1)
	R2 = R2 ^ R0
	R0 = 1701603183 # 0x656c676f 'ogle'
	R0,R3 = R3,R0
	R1 = 6
	R0 = hex2(R0,R1)
	R3 = R3 ^ R0
	R0 = 1852400160 # 0x6e696220 ' bin'
	R1 = 15
	R0 = hex3(R0,R1)
	R0 = R0 ^ R3
	R2, R3 = R3, R2 ^ R0
	R0 = 1747804522 # 0x682d616a 'ja-h'
	R1 = 28
	R0 = hex4(R0,R1)
	R0 = R0 ^ R3
	R2, R3 = R3, R2 ^ R0
	R0 = 1734441061 # 0x67617865 'exag'
	R1 = 45
	R0 = hex5(R0,R1)
	R0 = R0 ^ R3
	R2, R3 = R3, R2 ^ R0
	R0 = 706768495 # 0x2a206e6f 'on *'
	R1 = 66
	R0 = hex6(R0,R1)
	R0 = R0 ^ R3
	R2, R3 = R3, R2 ^ R0
	R4,R5 = struct.unpack('II',target)
	print(f'R2={hex(R2)} R3={hex(R3)} R4={hex(R4)} R5={hex(R5)}')
	return R5 == R3 and R4 == R2

def check_flag_reduced(target):
	r2,r3 = struct.unpack('II',b'AAAABBBB')
	R2 = ~(r2 + 173879092) ^ 1869029418
	R3 = ~r3 ^ 1210484339 ^ 1701603183
	R2, R3 = R3, R2 ^ 515279715 ^ R3 # hex3
	R2, R3 = R3, R2 ^ 1086499140 ^ R3 # hex4
	R2, R3 = R3, R2 ^ -1463925658 ^ R3 # hex5
	R2, R3 = R3, R2 ^ 1341079333 ^ R3 # hex6
	R4,R5 = struct.unpack('II',target)
	print(f'R2={hex(R2)} R3={hex(R3)} R4={hex(R4)} R5={hex(R5)}')
	return R5 == R3 and R4 == R2

def invert_flag(target):
	R2,R3 = struct.unpack('II',target)
	R2,R3 = R3 ^ R2 ^ 1341079333, R2
	R2,R3 = R3 ^ R2 ^ -1463925658, R2
	R2,R3 = R3 ^ R2 ^ 1086499140, R2
	R2,R3 = R3 ^ R2 ^ 515279715, R2
	r3 = ~(R3 ^ 1210484339 ^ 1701603183)
	r2 = ~(R2 ^ 1869029418) - 173879092
	print('Input:', struct.pack('II',r2 % 2**32,r3 % 2**32))

if __name__ == '__main__':
	with open('challenge','rb') as fhandle:
		fhandle.seek(0x515)
		data = fhandle.read(0x50)
		fhandle.close()

	data = list(data)
	R0 = 0x1337 # you'd think this was right ...
	R0 = 0x20228
	# R0 = main ; memw (Sp + 0x4) = R0 <--- sets R0, then overwrites return value?
	for i in range(0x50):
		data[i] = (data[i] ^ (R0+i)) & 0xff
	print(bytes(data))
	target = bytes(data)[:8]
	print('good:',bytes(data)[8:8+61])
	print('bad:',bytes(data)[8+61:8+61+11])
	print('target:',binascii.hexlify(target))

	check_flag(target)
	check_flag_reduced(target)
	invert_flag(target)
