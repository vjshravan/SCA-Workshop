######################################
# Author : Keerthi K, IIT Madras
######################################

import os
import subprocess
from random import randint
import argparse, sys
import array
import numpy as np
import aes as finj

POSITIONS = [[0, 13, 10, 7],[4, 1, 14, 11],[8, 5, 2, 15],[12, 9, 6, 3]]

def intersection(total_cand,candidates):
	#print(len(total_cand), len(candidates))
	nlen = 0
	for i in total_cand:
	 	for j in candidates:
	 		if i == j:
	 			total_cand = j
	 			break
	return total_cand


# given ciphertext (ct_list_i) and faulty ciphertext (fct_list_i), reverse
# the last round to obtain the difference equation for the output of the 9th round
def ReverseAESLastRound(ct_list_i,fct_list_i):
    delta_list = [1,2,4,8,16,32,64,128] 
    for k in range(0,256):
        diff = finj.isbox[ct_list_i ^ k] ^ finj.isbox[fct_list_i ^ k]
        for i in range(0,8):
            if diff == delta_list[i]:
                print(k," ")
    print ("\n")

def reverse_key(key10):
	subkeys = [0] * 176

	for i in range(160,176):
		subkeys[i] = key10[i - 160]

	for i in range(156,-1,-4):
		if i % 16 == 0 :
			subkeys[i] = subkeys[i + 16] ^ finj.sbox[subkeys[i + 13]] ^ finj.rcon[i>>4]
			subkeys[i + 1] = subkeys[i + 17] ^ finj.sbox[subkeys[i + 14]]
			subkeys[i + 2] = subkeys[i + 18] ^ finj.sbox[subkeys[i + 15]]
			subkeys[i + 3] = subkeys[i + 19] ^ finj.sbox[subkeys[i + 12]]
		else:
			subkeys[i] = subkeys[i + 16] ^ subkeys[i + 12]
			subkeys[i + 1] = subkeys[i + 17] ^ subkeys[i + 13]
			subkeys[i + 2] = subkeys[i + 18] ^ subkeys[i + 14]
			subkeys[i + 3] = subkeys[i + 19] ^ subkeys[i + 15]

	return subkeys

def matching_keys(pt, ct, total_cand, cand_len):
	#print(bytes(ct).hex())
	found = 0
	key10 = [0] * 16

	key10[0] = total_cand[0][0]
	key10[13] = total_cand[0][1]
	key10[10] = total_cand[0][2]
	key10[7] = total_cand[0][3]

	key10[4] = total_cand[1][0]
	key10[1] = total_cand[1][1]
	key10[14] = total_cand[1][2]
	key10[11] = total_cand[1][3]

	key10[8] = total_cand[2][0]
	key10[5] = total_cand[2][1]
	key10[2] = total_cand[2][2]
	key10[15] = total_cand[2][3]

	key10[12] = total_cand[3][0]
	key10[9] = total_cand[3][1]
	key10[6] = total_cand[3][2]
	key10[3] = total_cand[3][3]

	print("10th round Key ", key10)
	subkeys = reverse_key(key10)
	print(subkeys)
	ct1 = finj.encrypt_aes_subkeys(pt, subkeys)
	if (ct1.hex() == bytes(ct).hex()):
		print("Found the Key :", bytes(subkeys[0:16]).hex())
	return 1

	return 0
    
def exhaustive_search(pt, ct, total_cand, cand_len):
	found = 0
	key10 = [0] * 16
	#print(total_cand)

	llist = total_cand[0]
	for i in range(0, cand_len[0]):
		print("Validating: ", str(i + 1)+"/"+str(cand_len[0]))
		key10[0] = llist[i][0]
		key10[13] = llist[i][1]
		key10[10] = llist[i][2]
		key10[7] = llist[i][3]

		llist1 = total_cand[1]
		for j in range(0, cand_len[1]):
			key10[4] = llist1[j][0]
			key10[1] = llist1[j][1]
			key10[14] = llist1[j][2]
			key10[11] = llist1[j][3]

			llist2 = total_cand[2]
			for k in range(0, cand_len[2]):
				key10[8] = llist2[k][0]
				key10[5] = llist2[k][1]
				key10[2] = llist2[k][2]
				key10[15] = llist2[k][3]

				llist3 = total_cand[3]
				for l in range(0, cand_len[3]):
					key10[12] = llist3[l][0]
					key10[9] = llist3[l][1]
					key10[6] = llist3[l][2]
					key10[3] = llist3[l][3]
					print(key10)
					subkeys = reverse_key(key10)
					ct1 = finj.encrypt_aes_subkeys(pt, subkeys)
					if (ct1.hex() == bytes(ct).hex()):
						print("Found the Key :", bytes(subkeys[0:16]).hex())
						return 1

	return 0

def get_diff_MC(fault_list,fault_len):
	row_start = 0
	row_end = 4
	col = []
	col = [0] * 4
	list_diff = []
	for i in range(row_start,row_end):
		for j in range(0, fault_len):
			col = [0] * 4
			col[i] = fault_list[j]
			finj.mixcolumn(col)  # present in aes.py. Evaluates col=MixColumn(col)
			list_diff.append(col)

	return list_diff

# For all possible faults ie. delta, (ie, 1 to 255), identify all possible
# outputs of mix columns. For example (2delta, 3delta, delta, delta)
# the list of possible outputs is stored in list_diff

def FaultPos(ct_list_i,fct_list_i):
	for i in range(0,16):
		if ((ct_list_i[i] ^ fct_list_i[i]) != 0):
			print("Position: ", i)
			break
	return i

def round10_key_recovery(pt, ct, ct_list, fct_list, ln):
	print("10th round Analysis")
	for i in range(0,ln):
		print ("Iteration: ", i,"-")
		Pos = FaultPos(ct_list[i],fct_list[i])
		ReverseAESLastRound(ct_list[i][Pos],fct_list[i][Pos])
		
def bitstring_to_bytes(s):
    v = int(s, 2)
    b = []
    while v:
        b.append(int(v & 0xff))
        v >>= 8
    #print b
    return b[::-1]

def readfile(filename):
	ct_list = []
	fct_list = []
	print("Read the contents of the File")
	fn= open(filename,'r')
	cont = fn.readlines()
	type(cont) 
	data = cont[0].split(',')

	# load plaintext and ciphertext from first line
	pt = bitstring_to_bytes(bin(int(data[0], 16)))
	ct_t = data[1].replace('\n','')
	ct = bitstring_to_bytes(bin(int(ct_t, 16)))

	print("FaultyCiphertext")
	for i in range(1,len(cont)):
		data = cont[i].split(',')
		ct1 = bitstring_to_bytes(bin(int(data[0], 16)))
		print ("CiperText: ",ct1, "\n")
		ct_list.append(ct1)
		fct_t = data[1].replace('\n','')
		fct = bitstring_to_bytes(bin(int(fct_t, 16)))
		print ("Faulty CiperText: ",fct, "\n")
		fct_list.append(fct)
		print(bytes(fct).hex())
		
	return pt,ct, ct_list,fct_list, len(fct_list)

def parse_parameters():
    parser = argparse.ArgumentParser(description='Differential Fault Analysis')
    parser.add_argument("-round", help = "input the round where fault is injected", type=str, required=True)
    parser.add_argument("-input", help = "File containing ciphertext details", type=str, required=True)
    args = parser.parse_args()
    
    mode = int(args.round)
    filename = args.input
    found  = 0

    # Read input file
    # pt and ct are the first row of filename (not used in the program). 
    # ct_list and fct_list correpond to 2nd, 3rd, 4th, 5th row of input file (see README.md)
    # ln is the number of lines read from file
    pt,ct, ct_list,fct_list,ln = readfile(filename) 

    #ln = 1 # identify 4 bytes of the key corresponding to column 1

    if mode == 9:     # fault in 9th round
        print("Fault Injection in the 9th round\n")
        round9_key_recovery(pt, ct, ct_list, fct_list, ln)
    elif mode == 10:  # fault injected in 10th round
        round10_key_recovery(pt, ct, ct_list, fct_list, ln)

if __name__=="__main__":
	parse_parameters()
