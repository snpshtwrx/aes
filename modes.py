'''
Verschiedene Betriebsmodi für den AES

@Author: Yannic 
Version: 05/11/2021
Python-Version: 3.7.9 64-Bit
'''
import algorithm
import funcs

import numpy as np
import math

#Funktion für die Verschlüsselung eines einzigen Blocks
#Erwartet eingabe-Array, vollständig erweiterten Schlüssel als zweidimensionales Array und die Anzahl der Runden
def enc_aes(eingabe, schlüssel, runden):
    temp = algorithm.add_round_key(eingabe, schlüssel[0])
    for j in range(1, runden):
        temp = algorithm.substitute_bytes(temp)
        temp = algorithm.shift_rows(temp)
        temp = algorithm.mix_columns(temp)
        temp = algorithm.add_round_key(temp, schlüssel[j])
    temp = algorithm.substitute_bytes(temp)
    temp = algorithm.shift_rows(temp)
    temp = algorithm.add_round_key(temp, schlüssel[runden])
    return temp

#Funktion für die Enschlüsselung eines einzigen Blocks
#Erwartet ein eingabe-Array, vollständig erweiterten Schlüssel und die Anzahl der Runden
def dec_aes(eingabe, schlüssel, runden):
    temp = algorithm.add_round_key(eingabe, schlüssel[runden])
    for j in range(1, runden):
        temp = algorithm.inv_shift_rows(temp)
        temp = algorithm.inv_subsitute_bytes(temp)
        temp = algorithm.add_round_key(temp, schlüssel[runden - j])
        temp = algorithm.inv_mix_columns(temp)
    temp = algorithm.inv_shift_rows(temp)
    temp = algorithm.inv_subsitute_bytes(temp)
    temp = algorithm.add_round_key(temp, schlüssel[0])
    return temp

#Funktion für die Verschlüsselung mit dem ECB Modus
#Erwartet ein zweidimensionales eingabe-Array, einen vollständig erweiterten Schlüssel und die entsprechende Anzahl an Runden
def enc_ecb(eingabe, schlüssel, runden):
    end_result = np.array([], dtype=np.uint8)
    for i in range(np.shape(eingabe)[0]):
        temp = enc_aes(eingabe[i], schlüssel, runden)
        end_result = np.append(end_result, temp)
    return end_result

#Funktion für die Entschlüsselung des ECB Modus
def dec_ecb(eingabe, schlüssel, runden):
    end_result = np.array([], dtype=np.uint8)
    for i in range(np.shape(eingabe)[0]):
        temp = dec_aes(eingabe[i], schlüssel, runden)
        end_result = np.append(end_result, temp)
    return end_result

#Funktion für die Verschlüsselung mit dem CBC Modus
#Erwartet ein zweidimensionales eingabe-Array, vollständig erweiterten Schlüssel, die entsprechende Anzahl an Runden und einen 16-Byte langen Initialisierungsvektor als Array
def enc_cbc(eingabe, schlüssel, runden, iv):
    end_result = np.array([], dtype=np.uint8)
    temp = iv
    for i in range(np.shape(eingabe)[0]):
        temp = algorithm.add_round_key(eingabe[i], temp)
        temp = enc_aes(temp, schlüssel, runden)
        end_result = np.append(end_result, temp)
    return end_result

#Funktion für die Entschlüsselung mit dem CBC Modus
def dec_cbc(eingabe, schlüssel, runden, iv):
    end_result = np.array([], dtype=np.uint8)
    kopie = eingabe.copy()
    for i in range(np.shape(eingabe)[0]):
        temp = dec_aes(eingabe[i], schlüssel, runden)
        temp = algorithm.add_round_key(temp, iv if i == 0 else kopie[i - 1])
        end_result = np.append(end_result, temp)
    return end_result

#Funktion für die Ver- und Entschlüsselung mit dem Counter Modus
#Erwartet ein zweidimensionales eingabe-Array, einen vollständig erweiterten Schlüssel, die Anzahl der Runden und einen Initialisierungsvektor welcher 16 Bytes lang ist
def ctr(eingabe, schlüssel, runden, iv):
    end_result = np.array([], dtype=np.uint8)
    for i in range(np.shape(eingabe)[0]):
        counter = i
        temp = funcs.hexstring_als_array(hex(counter + int(funcs.array_als_hexstring(iv.copy()), 16))[2:])
        temp = enc_aes(temp, schlüssel, runden)
        temp = algorithm.add_round_key(eingabe[i], temp)
        end_result = np.append(end_result, temp)
    return end_result

#Verschlüsseln mit dem CFB Modus
def enc_cfb(eingabe, schlüssel, runden, iv):
    end_result = np.array([], dtype=np.uint8)
    temp = iv.copy()
    for i in range(np.shape(eingabe)[0]):
        temp = enc_aes(temp, schlüssel, runden)
        temp = algorithm.add_round_key(temp, eingabe[i])
        end_result = np.append(end_result, temp)
    return end_result

#Entschlüsseln mit dem CFB Modus
def dec_cfb(eingabe, schlüssel, runden, iv):
    end_result = np.array([], dtype=np.uint8)
    temp = iv.copy()
    for i in range(np.shape(eingabe)[0]):
        temp = enc_aes(temp, schlüssel, runden)
        temp = algorithm.add_round_key(temp, eingabe[i])
        end_result = np.append(end_result, temp)
        temp = eingabe[i]
    return end_result

#Ver- und Entschlüsseln mit dem OFB Modus
def ofb(eingabe, schlüssel, runden, iv):
    end_result = np.array([], dtype=np.uint8)
    temp = iv.copy()
    for i in range(np.shape(eingabe)[0]):
        temp = enc_aes(temp, schlüssel, runden)
        out = algorithm.add_round_key(temp.copy(), eingabe[i])
        end_result = np.append(end_result, out)
    return end_result

 #Der Code unterhalb dieser Zeile ist nicht im Programm nutzbar, da der GCM Modus nicht fertig gestellt wurde (aufgrund von Verständnis Problemen beim Implementieren)
def enc_gcm(eingabe, schlüssel, runden, iv, aad):
    end_result = np.array([], dtype=np.uint8)
    hashkey = enc_aes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], schlüssel, runden)
    y = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    icb = ghash(iv.copy(), hashkey, y)
    temp = gctr(iv.copy(), eingabe, schlüssel, runden)
    end_result = np.append(end_result, temp)
    u = 128 * np.shape(eingabe)[0] - np.shape(eingabe)[0]
    #v = 128 * np.shape(aad)[0] - np.shape(aad)[0]
    s = np.array([], dtype=np.uint8)
    for i in range(np.shape(eingabe)[0]):
        pass
    end_result = np.append(end_result, s)
    return end_result

def inc_s(bit_string, s):
    return bit_string[:len(bit_string) - s] +  '{0:0{1}b}'.format((int(bit_string[len(bit_string) - s:], 2) + 1) % (2**s), s)

def gctr(icb, eingabe, schlüssel, runden):
    ausgabe = np.array([], dtype=np.uint8)
    n = np.shape(eingabe)[0]
    cb = icb
    for i in range(n):
        ausgabe = np.append(ausgabe, algorithm.add_round_key(eingabe[i], enc_aes(cb, schlüssel, runden)))
        cb = funcs.bitstring_als_array(inc_s(funcs.array_als_bitstring(cb), 32))
    return funcs.array_aufteilen_zero_padding(ausgabe)

def ghash(b1, hashkey, y):
    return funcs.mul_block(algorithm.add_round_key(b1, y), hashkey)
