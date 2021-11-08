'''
Funktionen für den Advanced Encryption Standard (AES)

@Author: Yannic
Version: 07/09/2021
Python-Version: 3.7.9 64-Bit
'''

#Libraries:
#Numpy für Arrays mit uint8 (8 bit unsigned integer --> Werte von 0 bis 255) und schnelleren Array Operationen
import numpy as np

#Math für die Funktion ceil() (Aufrunden von Gleitkommazahlen zum nächst höheren Integer)
import math


#Substitutionstabelle als Array für die Funktion substitute_bytes() und die Schlüsselerweiterung
#uint8 den wenigsten Speicherplatz einzunehmen
sbox = np.array([
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
], dtype=np.uint8)

#Inverse Substitutionstabelle für die Funktion inv_substitute_bytes()
inv_sbox = np.array([
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
], dtype=np.uint8)

#2-Dimensionales keys-Array in welchem die Schlüssel gespeichert werden
#Bei Aufrufen des Scripts mit Nullen gefüllt --> 15 Zeilen mit je 16 Spalten (nur bei AES-256 werden alle 15 Zeilen für die Schlüssel benötigt)
keys = np.zeros((15, 16), dtype=np.uint8)

#Array mit den Rundenkoeffizienten für die Schlüsselerweiterung
runden_koeffizienten = np.array([
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
], dtype=np.uint8)

#Variable anzahl_runden welche als Ausgangswert auf 10 festgelegt ist
#Wird je nach Schlüssellänge in der key_expansion()-Funktion angepasst
anzahl_runden = 10

#Funktion substitute_bytes(eingabe) mit dem Übergabeparameter eingabe, welche ein 16-stelliges Array mit Bytes (in Form von Integern) erwartet
#Der Wert an der i-ten Stelle von eingabe wird als Index für die sbox verwendet, der Wert an der Stelle überschreibt eingabe[i]
#Nachdem alle Bytes ersetzt wurden wird das eingabe-Array zurückgegeben
def substitute_bytes(eingabe):
  for i in range(16):
    eingabe[i] = sbox[eingabe[i]]
  return eingabe

#inv_substitute_bytes(eingabe) funktioniert nach dem selben Prinzip wie substitute_bytes() nur mit inv_sbox anstatt sbox
def inv_subsitute_bytes(eingabe):
    for i in range(16):
        eingabe[i] = inv_sbox[eingabe[i]]
    return eingabe

#shift_rows(eingabe) erhält auch ein 16-stelliges Array als Übergabeparameter
#Die Funktion weißt die einzelnen Elemente neu zu und gibt dann eingabe zurück
'''
Visualisierung (Zahlen in Hexadezimal):
eingabe = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F]
kann man sich vorstellen als 4x4-Matrix
    0 4 8 C
    1 5 9 D
    2 6 A E
    3 7 B F
diese Matrix wird dann rotiert und wir erhalten
    0 4 8 C
    5 9 D 1
    A E 2 6
    F 3 7 B
--> eingabe = [0, 5, A, F, 4, 9, E, 3, 8, D, 2, 7, C, 1, 6, B]
'''
def shift_rows(eingabe):
    eingabe[1], eingabe[5], eingabe[9], eingabe[13] = eingabe[5], eingabe[9], eingabe[13], eingabe[1]
    eingabe[2], eingabe[6], eingabe[10], eingabe[14] = eingabe[10], eingabe[14], eingabe[2], eingabe[6]
    eingabe[3], eingabe[7], eingabe[11], eingabe[15] = eingabe[15], eingabe[3], eingabe[7], eingabe[11]
    return eingabe

#inv_shift_rows(eingabe) rotiert alle Bytes entgegen der Richtung von shift_rows()
def inv_shift_rows(eingabe):
    eingabe[1], eingabe[5], eingabe[9], eingabe[13] = eingabe[13], eingabe[1], eingabe[5], eingabe[9]
    eingabe[2], eingabe[6], eingabe[10], eingabe[14] = eingabe[10], eingabe[14], eingabe[2], eingabe[6]
    eingabe[3], eingabe[7], eingabe[11], eingabe[15] = eingabe[7], eingabe[11], eingabe[15], eingabe[3]
    return eingabe

#Die Funktion mix_columns(eingabe) wieder mit dem selben Übergabeparameter wie die vorigen Funktionen multipliziert die eingabe mit einer festen Matrix M im Erweiterungskörper GF(2^8)
'''
Visualisierung (eingabe wird wie bei shift_rows() in einer 4x4-Matrix angeordnet):
       M     *  eingabe                                                         eingabe'
    2 3 1 1     0 4 8 C 	2*0^3*1^2^3 2*4^3*5^6^7 2*8^3*9^A^B 2*C^3*D^E^F     2 6 A E
    1 2 3 1  *  1 5 9 D  =  0^2*1^3*2^3 4^2*5^3*6^7 8^9^2*A^3*B 3*C^D^E^2*F  =  7 3 F B
    1 1 2 3     2 6 A E     0^1^2*2^3*3 4^5^2*6^3*7 8^9^2*A^3*B C^D^2*E^3*F     0 4 8 C
    3 1 1 2     3 7 B F     3*0^1^2^2*3 3*4^5^6^2*7 3*8^9^A^2*B 3*C^D^E^2*F     5 1 D 9
^ steht in der Rechnung und im Code für XOR (Exklusives-Oder)
--> eingabe = [2, 7, 0, 5, 6, 3, 4, 1, A, F, 8, D, E, B, C, 9]
'''
#Im Code wird pro Runde der for-Schleife eine Reihe (Column) des Ergebnis berechnet
#Um das Element XY des Ergebnises zu erhalten wird die Zeile X von M mit der Reihe Y von eingabe multipliziert
#In der ersten Runde der for-Schleife ist temp0 der Zwischenspeicher für das Element 00 vom Ergebnis, temp1 speichert dann das Element 10 und so weiter...
def mix_columns(eingabe):
    for i in range(4):
        temp0 = mul_2(eingabe[i*4]) ^ mul_3(eingabe[i*4+1]) ^ eingabe[i*4+2] ^ eingabe[i*4+3]
        temp1 = eingabe[i*4] ^ mul_2(eingabe[i*4+1]) ^ mul_3(eingabe[i*4+2]) ^ eingabe[i*4+3]
        temp2 = eingabe[i*4] ^ eingabe[i*4+1] ^ mul_2(eingabe[i*4+2]) ^ mul_3(eingabe[i*4+3])
        temp3 = mul_3(eingabe[i*4]) ^ eingabe[i*4+1] ^ eingabe[i*4+2] ^ mul_2(eingabe[i*4+3])
        eingabe[i*4], eingabe[i*4+1], eingabe[i*4+2], eingabe[i*4+3] = temp0, temp1, temp2, temp3
    return eingabe

#inv_mix_columns(eingabe) multipliziert eingabe mit der Matrix M^-1
'''
M * M^-1 = I

        E B D 9
M^-1 =  9 E B D
        D 9 E B
        B D 9 E
'''
def inv_mix_columns(eingabe):
    for i in range(4):
        temp0 = mul_E(eingabe[i*4]) ^ mul_B(eingabe[i*4+1]) ^ mul_D(eingabe[i*4+2]) ^ mul_8(eingabe[i*4+3]) ^ eingabe[i*4+3]
        temp1 = mul_8(eingabe[i*4]) ^ eingabe[i*4] ^ mul_E(eingabe[i*4+1]) ^ mul_B(eingabe[i*4+2]) ^ mul_D(eingabe[i*4+3])
        temp2 = mul_D(eingabe[i*4]) ^ mul_8(eingabe[i*4+1]) ^ eingabe[i*4+1] ^ mul_E(eingabe[i*4+2]) ^ mul_B(eingabe[i*4+3])
        temp3 = mul_B(eingabe[i*4]) ^ mul_D(eingabe[i*4+1]) ^ mul_8(eingabe[i*4+2]) ^ eingabe[i*4+2] ^ mul_E(eingabe[i*4+3])
        eingabe[i*4], eingabe[i*4+1], eingabe[i*4+2], eingabe[i*4+3] = temp0, temp1, temp2, temp3
    return eingabe

#Die Funktion mul_2(eingabe_byte) ist essentiell für die Funktion mix_columns() und inv_mix_columns()
#Diese Funktion implementiert die Multiplikation mit 2 im Erweiterungskörper GF(2^8), basierend darauf kann man alle Multiplikationen im Erweiterungskörper ausführen
#Dient als Basis für die Funktionen mul_3(), mul_4(), mul_8(), mul_B(), mul_D() und mul_E()
#Zuerst wird eingabe_byte mit 2 multipliziert dann wird das Ergebnis modulo 256 gerechnet, sodass Zahlen welche größer als 255 nicht als Ergebnis zurückgegeben werden können
#Wenn das eingabe_byte größer als 128-Bit ist (also 0x80) wird der erste Teil mit 0x1B = 27 XOR gerechnet (bildet in Verbindung mit dem modulo 256 die Reduktion mit dem irreduziblen Polynom von AES)
def mul_2(eingabe_byte):
    return (((eingabe_byte * 2) % 256) ^ (0x1B if (eingabe_byte >= 0x80) else 0x00))

def mul_3(eingabe_byte):
    return mul_2(eingabe_byte) ^ eingabe_byte

def mul_4(eingabe_byte):
    return mul_2(mul_2(eingabe_byte))

def mul_8(eingabe_byte):
    return mul_2(mul_4(eingabe_byte))

def mul_B(eingabe_byte):
    return mul_8(eingabe_byte) ^ mul_3(eingabe_byte)

def mul_D(eingabe_byte):
    return mul_8(eingabe_byte) ^ mul_4(eingabe_byte) ^ eingabe_byte

def mul_E(eingabe_byte):
    return mul_8(eingabe_byte) ^ mul_4(eingabe_byte) ^ mul_2(eingabe_byte)

#Die Funktion add_round_key(eingabe, key) erwartet zwei 16-stellige Arrays als Übergabe und disjungiert die Elemente der Arrays kontravalent
def add_round_key(eingabe, key):
    for i in range(16):
        eingabe[i] = eingabe[i] ^ key[i]
    return eingabe

#Die key_expansion(key, index) Funktion erwartet ein 16-stelliges Array (key) und einen Integer (index)
def key_expansion(key, index):
    global anzahl_runden
    if(index == 0):
        for i in range(16):
            keys[0][i] = key[i]
        if(len(key) == 24):
            for i in range(8):
                keys[1][i] = key[16 + i]
            anzahl_runden = 12
        elif(len(key) == 32):
            for i in range(16):
                keys[1][i] = key[16 + i]
            anzahl_runden = 14
            index += 1
        index += 1
    
    if(anzahl_runden == 10 and index < 11):
        keys[index][0] = key[0] ^ (sbox[key[13]] ^ runden_koeffizienten[index - 1])
        keys[index][1] = key[1] ^ (sbox[key[14]])
        keys[index][2] = key[2] ^ (sbox[key[15]])
        keys[index][3] = key[3] ^ (sbox[key[12]])

        for i in range(12):
            keys[index][i + 4] = key[i + 4] ^ keys[index][i]
        key_expansion(keys[index], index + 1)

    elif(anzahl_runden == 12 and index < 13):
        startIndex = 8 if index % 3 == 1 else 0

        rc_index = 0
        if index == 3 or index == 4:
            rc_index = index - 2
        elif index == 6 or index == 7:
            rc_index = index - 3
        elif index == 9 or index == 10:
            rc_index = index - 4
        elif index == 12:
            rc_index = index - 5

        keys[index][startIndex] = key[0] ^ (sbox[key[21]] ^ runden_koeffizienten[rc_index])
        keys[index][startIndex + 1] = key[1] ^ (sbox[key[22]])
        keys[index][startIndex + 2] = key[2] ^ (sbox[key[23]])
        keys[index][startIndex + 3] = key[3] ^ (sbox[key[20]])

        if startIndex == 8:
            for i in range(4):
                keys[index][startIndex + 4 + i] = keys[index][startIndex + i] ^ key[4 + i]
            for i in range(4):
                keys[index + 1][i] = keys[index][12 + i] ^ key[8 + i]
            for i in range(12):
                keys[index + 1][i + 4] = key[12 + i] ^ keys[index + 1][i]
        else:
            for i in range(12):
                keys[index][i + 4] = key[i + 4] ^ keys[index][i]
            for i in range(4):
                keys[index + 1][i] = key[i + 16] ^ keys[index][i + 12]
            for i in range(4):
                keys[index + 1][4 + i] = key[i + 20] ^ keys[index + 1][i]

        temp_key = np.append(keys[index][8:16], keys[index + 1]) if index % 3 == 1 else np.append(keys[index], keys[index + 1][0:8])
        key_expansion(temp_key, index + (2 if index % 3 == 1 else 1))
        
    elif(anzahl_runden == 14 and index < 15):
        keys[index][0] = key[0] ^ (sbox[key[29]] ^ runden_koeffizienten[int(index/2) - 1])
        keys[index][1] = key[1] ^ (sbox[key[30]])
        keys[index][2] = key[2] ^ (sbox[key[31]])
        keys[index][3] = key[3] ^ (sbox[key[28]])

        for i in range(12):
            keys[index][i + 4] = key[i + 4] ^ keys[index][i]

        if(index + 1 < 15):
            keys[index + 1][0] = sbox[keys[index][12]] ^ key[16]
            keys[index + 1][1] = sbox[keys[index][13]] ^ key[17]
            keys[index + 1][2] = sbox[keys[index][14]] ^ key[18]
            keys[index + 1][3] = sbox[keys[index][15]] ^ key[19]

            for i in range(12):
                keys[index + 1][i + 4] = key[i + 20] ^ keys[index + 1][i]
            key_expansion(np.append(keys[index], keys[index + 1]), index + 2)

    return keys

def get_anzahl_runden():
    return anzahl_runden