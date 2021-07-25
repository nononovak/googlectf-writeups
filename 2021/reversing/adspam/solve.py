#!/usr/bin/env python3

import struct
import socket
import binascii
import base64
import json
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

LICENSE = '''
QIknTsIjeUEF9yJjeZ/kPPfTlSm8vzMU4LWjzfSXvN+OSqBu3iNgZJgeW7fc8oltH9MprO9nI8vxgsjO/VA4t7YuNm16a7elPVAHqD4dXtzngnZPpsbek3Rc/We/WQ5YxXHgUt7YJ6tcd4wH3fhduC9tl/E5elwJL/YAcbD4mT8=
o9kjqYWCBKMgodl1JvDiscUeRjh9Ip9HcC7tHskoYqNQfAPE0XvSAKBSOFgleNHzVY9BVkfxmutgn/kVXUs3yl/qAurc4jokg0eA/v3flnnkWxqTOh4vv0yfr7PGXqwHk4qUFK1SldZ4VsLhd8PAb0aHj22E5b4U5jeJ16z187E=
gpDbCb0BmUZfdKVIZgF08lQ80K9SeUsRadZG+UUjE7wI1NRZ1evLk2GQ3sqskGHFKlPg8cTR2Xy69WedNu4QLboOWm/w13ocOvHwCoiQ1ZdmibgnhMQBznqpjpBnL083YMRYskcUX68R2PFaXY3taV7MoG1DyQWFRfdr/CnLyS8=
ZBLhwMu0DbgpUANm2ukYldrppJERiH1Tgp02CRB5I4dDP8n4+ZCv33ScspELtgAKHhiwIVksQVsnwDLsQRi6nqq9nrIwqSHMR0TwOe6UKTpAegbH53FXtriopPHfLuI2M45SzJ88GFjXy7wfOOjwDYe4KKO9KU8+LGD15Au73EM=
Hygv+bTtsnI9IBf44GkvoF38r3g5zBB7uyYT7PTlbjhCdgYRwRayutI3vY+n66xM7GOFgUFVIBI5+OBDnvazLNttjGomPED/OXlImndWvrZxYcaKaE3vYGPezorV0xwPahGGq/DWafPKdYxLxwICq1GXKYNAckCZIqfpGbJRRwg=
GARMZAX7fQN7i7Wnp4J6HxMTLe9+VM/wGJs+zN6b9IOmynh2gIkGjmssfOA9KdYydqBLEOJymayH8HeyrtInhhQNR3el8A5n8GMEMkyF1gUFAiSEPyhNeWWOj2IAHGNNwccmF7QywdfOUGjsTNFbrW6Yl5QLLAmMbA95qF0IERk=
YWlx8Cok1x/3ZsW9JKIsKj9UpBaCNkXSPiVXUrNX1IDZE0B8iNr3iliOr90TW0BvsIaFEwvDTlcESXJ8kLc3iZq0fm1lgujfM7Z156VdxEPjr9LplcEZ9ZVhYGNtVyGIRcouUDJHu3FVfXQ1XesaNlNHOb50hADprsw3RnTAGbU=
I3dsx2vSfXxZ1/QlMbwYPRFEZBtOuB8qLEY8cqFVtYjMluNWSkbHAYB+kwCBEv3yuoOjkdQEfqq4pS+K0ka1+pFDyss8sSbV3OiZdpRf40SS/pZxw2duJr9uDd1DdX8mST7fdjqj0V1a2ZBMpqaEI2gFlCwzXlfZBC47LKNiM+8=
ow7r5VJMGfSf0odNKxzBpUtSJdj8gHdt+Z7Xu54MAdsnUParSjrtRI4yJYzcW4toOFmDdSs5SERR289yohYI5hHSWLElv/44O+g4M08F5qpwCmOp5otW32qRG1RnhqR95evH44nOyK24UnpvWlebNwVhniSu4A7znjluGRrao/U=
TeGqGWv8ZmsY/rFq1puW9N+01TWTKJm8qzUuY/7JUCPDJ1AR6Y3XsPb73FuSVHPL63sjiuCTiKTRSUDzBE0VBfo59rtOKI05k64Jrz88nODD7BiK7ssacsOr2dAFGQKgBaWV2jitSAdxtCmh9sDpYsfs0/vXBBfVLqfVZDfAVGQ=
Al3QWY+nNFoLezt+rSdbWmqp7iZ+rR9pnM35IJNZ63bLQeM3CUvULVczhrM3toXNLCY7xmAT4jg+u0uDAjanaKMB+T1Tmym7aaCqwCfHYVFn5nw+tw54e13CLxj7OO+e847+XH8DtK/BiA+n03vPnt/cEDPvIM59sPsjHThJvpk=
VOGr60qxiO1r0YlKnrIWbQu7UhBmtBeNw2NDQnoNU3H1mjVEs/ji3AYuEGc2HGKINByq7Mpb4mWKD2oH5ii/UZDpxbzCFlJrjvjEG25c9Hhf2fiQHvRXmJd8iA8YdffBii3csCjaydLFSX6Vn7XPg+/PF/TdM1zUiLTJZX4LXRw=
ELL9maLDpdmmEgaT76qtw9IugtaQX2r7V7QVqMKXQcbwq7o0dvaO3+yMt6m5K5Milm4JSNwX/810YUaoAsHNuaIavuLRsxbP3b6KnKxaKz3EDgyhye2en3U1EZouiLljBB0bKz8rAtyGdolWDdNoKjvLhv7x2edc05HQZOt3aiA=
'''.strip()

def decode_string(st):
	if type(st) == bytes:
		st1 = st
	else:
		st1 = binascii.unhexlify(st)
	st2 = b'cFUgdW9ZIGV2aUcgYW5ub0cgcmV2ZU4='
	return bytes(st1[i]^st2[i%32] for i in range(len(st1)))

def print_strings():
	print('# 001ad884')
	print(decode_string('02227a14143654750726225b173022033827411010'))
	print(decode_string('173434091731562824'))
	print(decode_string('0c2d2108162257'))
	print(decode_string('062836151d274d'))
	print(decode_string('072336151d274d'))
	print(decode_string('0723360b0d344a2e3b'))
	print(decode_string('4c3627080778573f3d68235c082d'))
	print(decode_string('05343c0305794a3f3b313340'))

	print('# 001ad9b4')
	print(decode_string('220306'))
	print(decode_string('311514'))
	print(decode_string('092723061c785a283037225d4e2613023a7866100142061328082f612a3057'))
	print(decode_string('092723061c785a283037225d4e160a17313247'))
	print(decode_string('5f2f3b0e1069'))
	print(decode_string('0423212e0a244d3b272433'))
	print(decode_string('0a283c13'))
	print(decode_string('0729130e0a3655'))
	print(decode_string('092723064b245c393c353f46187a280220115416165f111e'))
	print(decode_string('04233b0216364d3f1932345e0836'))
	print(decode_string('4b1d172b0e364f3b662b375c067a30132b3e5b12591935'))
	print(decode_string('4b0a3f06123616362829311d3221110e37300e5c2e5a021102157951282c44490c69160e143f5c2872'))
	print(decode_string('4b0f190d052158753a223547133c171e761c500c591935'))
	print(decode_string('4b0a3f06123616362829311d3221110e37300e5c2e5a02110242255739204654173f7a2c012e7f3b2a333940186e'))
	print(decode_string('4b0a3f06123616292c24234008211a482a2750164d7b061e301d3351617c78570230344817325a2f3b2e224b4e051605353e563e074958'))

	print('a/a/d.java')
	print(decode_string(bytes([12, 53, 10, 17, 1, 37, 74, 51, 38, 41])))
	print(decode_string(bytes([2, 54, 60, 56, 8, 50, 79, 63, 37])))
	print(decode_string(bytes([7, 35, 35, 14, 7, 50])))
	print(decode_string(bytes([13, 39, 56, 2])))
	print(decode_string(bytes([10, 53, 10, 6, 0, 58, 80, 52])))
	print(decode_string(bytes([7, 35, 35, 14, 7, 50, 102, 51, 39, 33, 57])))
	print(decode_string(bytes([15, 47, 54, 2, 10, 36, 92])))

	print('# 001af141')
	print(decode_string('092723064b245c393c353f46187a10173c341a2d57005a220d0e39563f317f581a15250207'))

	with open('adspam_publickey.der','wb') as fhandle:
		fhandle.write(binascii.unhexlify('30819f300d06092a864886f70d010101050003818d0030818902818100b001bf31dbc6a247cacca8d279550720a0bf9357435e46552c65e536ce717ab6099d4aafc79ffd19e46444846b7613368ed6bf47867133691f35eab8e9e5368822eecc73c400d82722a8f396d221fefe455437fa4b59b0645ceb5d1e42dd97eba8182b374452afc41ac19bb459b0d02dbcd5e93b7cfb50cce8a8ae4ddd06c1770203010001'))
		fhandle.close()
	#os.system('openssl rsa -pubin -inform der -in adspam_publickey.der -out adspam_publickey.pem')


def send_payload(jdata):
	aes = AES.new(b"eaW~IFhnvlIoneLl",AES.MODE_ECB)

	data = json.dumps(jdata).encode()
	pad = (-len(data))%16
	data = data + bytes([pad]*pad)
	print(f'send: encrypt({data})')

	encdata = aes.encrypt(data)

	s = socket.socket()
	s.connect(('adspam.2021.ctfcompetition.com',1337))
	assert s.recv(1024) == b'== proof-of-work: disabled ==\n'
	s.send(base64.b64encode(encdata)+b'\n')
	resp = s.recv(1024)
	print(f'recv: {resp}')
	decdata = aes.decrypt(base64.b64decode(resp))
	print(f'decrypted: {decdata}')

def decrypt_license():
	r = RSA.import_key(open('adspam_publickey.der','rb').read())

	arr = []
	#for line in open('app-release/resources/res/raw/lic'):
	for line in LICENSE.splitlines():
		cip = base64.b64decode(line.strip())
		res = pow(int.from_bytes(cip,'big'),r.e,r.n)
		arr.append(res)
		print(hex(res))
	print(struct.pack('>'+'I'*len(arr),*tuple(arr)))

if __name__ == '__main__':
	print_strings()
	decrypt_license()

	#send_payload({})

	#lines = [line.strip() for line in open('app-release/resources/res/raw/lic').readlines()]
	lines = [line.strip() for line in LICENSE.splitlines()]
	#lic = '::'.join(lines) + '::'
	lic = '::'.join(lines[:-1]+lines[8:9]*13) + '::'
	send_payload({"name":"1337_hacker$","is_admin":1,"device_info":{"os_version":"??","api_level":30,"device":"??"},"license":lic})
