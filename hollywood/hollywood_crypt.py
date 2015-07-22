#!/usr/bin/python3

# This decrypts the protected µCTF Hollywood code ("stage2") and writes it to a file suitable for opening with IDA

# We re-implement the Hollywood function that decrypts code before execution
# If X is the address of the value to decrypt, we use X+2 as the key and *X as the value to decrypt
# Some unit tests are included, because the web emulator doesn't match the MSP430 spec I have wrt flags, so this works empirically

import struct
from operator import add

# Format a word for hex output
def fmtw(w):
	return '0x'+format(w, '04X')

# Is this signed number positive?
def positive(x):
	return x<0x8000

# add x to y, returns (sr, result)
def add(x, y):
	r = x+y
	v=0
	c = r>=0x10000
	r %= 0x10000
	if positive(x) and positive(y) and not positive(r):
		v=1
	if not positive(x) and not positive(y) and positive(r):
		v=1
	n=not positive(r)
	z=r==0
	v=0 # The spec says we need to take V into account, but the web emulator never does ?
	sr = 0x100*v + 4*n + 2*z + c
	return sr, r

# sub x to y, returns (sr, result)
def sub(x, y):
	x = (((~x)&0xFFFF) + 1) & 0xFFFF
	return add(x, y)

# decimal addition, returns (sr, result)
def bcd_add(a, b, sr=None):
	if sr is None: sr=0
	h = [0, 0, 0, 0]
	c = [0, 0, 0, 0]
	f = lambda n : n# n+6 if n>=0xA else n
	a = [f(a>>12&0xF), f(a>>8&0xF), f(a>>4&0xF), f(a>>0&0xF)]
	b = [f(b>>12&0xF), f(b>>8&0xF), f(b>>4&0xF), f(b>>0&0xF)]
	for i in range(4):
		if a[i]>9 or b[i]>9 or a[i]+b[i]>9:
			h[i]=6
	r = [sum(x) for x in zip(a, b)]
	r = [sum(x) for x in zip(r, h)]
	for i in [3,2,1,0]:
		#print('r['+str(i)+'] is '+fmtw(r[i])+', c['+str(i)+'] is '+fmtw(c[i]))
		if i<3 and c[i+1]:
			if r[i]==0x9:	r[i]=0x10
			else:		r[i]+=1
		while r[i]>=0x10:
			c[i]=1
			r[i] -= 0x10
		#print('r['+str(i)+'] is '+fmtw(r[i])+', c['+str(i)+'] is '+fmtw(c[i]))
	r = (r[0]<<12) + (r[1]<<8) + (r[2]<<4) + (r[3]<<0)
	sr &= 0xFFFE	# We only affect the C flag and ignore the rest
	if c[0]: 	sr |= 1 # Set the carry on decimal overflow
	return sr, r


def cryptWord(addr, value):
	key=addr
	key=struct.unpack("<H", struct.pack(">H", key))[0]
	sr, key = sub(0x4D2, key)
	sr, key = add(sr, key)
	key = (0x8000*(sr&1)) | (key>>1)
	sr, key = bcd_add(key,addr,sr)
	if positive(key): 	key >>= 1
	else:			key = (0x8000) | (key>>1)
	key = (0x8000*(sr&1)) | (key>>1)
	sr, key = bcd_add(key,0x3C01, sr)
	sr, key = add(sr, key)
	key = (0x8000*(sr&1)) | (key>>1)
	sr, key = add(0x100E, key)
	newsr=key&1
	key = (0x8000*(sr&1)) | (key>>1)
	sr=newsr
	key = (0x8000*(sr&1)) | (key>>1)
	value ^= key
	return value;

def testDADD(x,y,e):
	r=bcd_add(x, y)[1]
	if r==e:
		print('[OK  ] DADD result of '+fmtw(x)+'+'+fmtw(y)+' is '+fmtw(r)+', expected '+fmtw(e))
	else:
		print('[FAIL] DADD result of '+fmtw(x)+'+'+fmtw(y)+' is '+fmtw(r)+', expected '+fmtw(e))

def testCrypt(x,y,e):
	r=cryptWord(x, y)
	if r==e:
		print('[OK  ] Crypt result of '+fmtw(x)+','+fmtw(y)+' is '+fmtw(r)+', expected '+fmtw(e))
	else:
		print('[FAIL] Crypt result of '+fmtw(x)+','+fmtw(y)+' is '+fmtw(r)+', expected '+fmtw(e))

# Test vectors
def test():
	testDADD(0, 0, 0)
	testDADD(2, 2, 4)
	testDADD(8, 8, 0x16)
	testDADD(0xA, 0, 0x10)
	testDADD(0xD, 0, 0x13)
	testDADD(0x10, 0, 0x10)
	testDADD(0xAA, 0, 0x110)
	testDADD(0x21, 0x33, 0x54)
	testDADD(0x160E, 0x04A2, 0x2116)
	testDADD(0xF, 0x0, 0x15)
	testDADD(0xF, 0x4, 0x19)
	testDADD(0xF, 0x5, 0x1A)
	testDADD(0xF, 0xA, 0x1F)
	testDADD(0xDD0, 0, 0x1430)
	testDADD(0x3C01, 0, 0x4201)
	testDADD(0xF00, 0x100, 0x1600)
	testDADD(0x3F00, 0x100, 0x4600)
	testDADD(0x3F00, 0xA00, 0x4F00)
	testDADD(0x3C01, 0xDD0, 0x4031)
	testDADD(0xC, 0xE, 0x10)
	testDADD(0xF, 0x1, 0x16)
	testDADD(0xC, 0xDD, 0x14f)
	testDADD(0xC0, 0xDD, 0x103)
	testDADD(0x1299, 0x3C01, 0x5500)
	testDADD(0x76A4, 0x16F2, 0x93F6)
	testDADD(0x3C01, 0x653E, 0x0745)
	testDADD(0x3C01, 0x1A28, 0x5C29)
	testCrypt(0x160E, 0x0F7D, 0x8231)
	testCrypt(0x1610, 0x4D68, 0x403C)
	testCrypt(0x1612, 0xC482, 0x49EA)
	testCrypt(0x1614, 0xC064, 0x4D00)
	testCrypt(0x1616, 0x0DF9, 0x8095)
	testCrypt(0x1618, 0x9D40, 0x9034)
	testCrypt(0x161A, 0xF339, 0xFEB1)
	testCrypt(0x1858, 0x4EB4, 0x4032)
	testCrypt(0x185A, 0x8E8E, 0x8000)
	testCrypt(0x185C, 0x4E9F, 0x403C)
	testCrypt(0x185E, 0x4661, 0x48CA)
	testCrypt(0x1738, 0x4CB8, 0x40B1)
	testCrypt(0x16F2, 0x1640, 0x12B0)
	testCrypt(0x16F4, 0x84FC, 0x0010)
	testCrypt(0x1A92, 0xCF3D, 0x40B1)
	testCrypt(0x1A94, 0x0FE8, 0x0061)
	testCrypt(0x1578, 0x4E5E, 0x40B1)
	testCrypt(0x157A, 0x0F77, 0x0074)
	testCrypt(0x157C, 0x8F0D, 0x0006)
	testCrypt(0x157E, 0xCF3B, 0x403C)
	testCrypt(0x1580, 0x4669, 0x4966)
	testCrypt(0x1BF6, 0xC814, 0x4D00)

test()
#import sys; sys.exit(0)

with open('hollywood_stage2_crypt', 'rb') as src:
	with open('hollywood_stage2_decrypted', 'wb') as dst:
		addr = 0x1400
		while 1:
			byte_s = src.read(2)
			if not byte_s:
				break
			word = byte_s[0]+(byte_s[1]<<8)
			addr += 2
			r = cryptWord(addr, word)
			#print(fmtw(word)+' -> '+fmtw(r))
			dst.write(bytes([r&0xFF, (r>>8)&0xFF]))




