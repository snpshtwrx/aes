'''
Hilfsfunktionen für den Advanced Encryption Standard (AES)

@Author: Yannic
Version: 03/11/2021
Python-Version: 3.7.9 64-Bit
'''
import numpy as np
import math
import algorithm

#Einen Eingabe-String in ein Array umwandeln
def string_in_array_umwandeln(eingabe):
    ausgabe = np.zeros(len(eingabe), dtype=np.uint8)
    for i in range(len(eingabe)):
        ausgabe[i] = ord(eingabe[i])
    return ausgabe

#Ein Eingabe-Array in einen String umwandeln
def array_in_string_umwandeln(eingabe):
    ausgabe = ""
    for byte in eingabe:
        ausgabe = ausgabe + chr(byte)
    return ausgabe

#Das eingegebene Array aufteilen und den letzten unvollständigen Block mit Nullen auffüllen
def array_aufteilen_zero_padding(eingabe):
    ausgabe = np.zeros((math.ceil(len(eingabe)/16), 16), dtype=np.uint8)
    for i in range(math.ceil(len(eingabe)/16)):
        length = 16 if ((i + 1) * 16) <= len(eingabe) else (len(eingabe) % 16) 
        for j in range(length):
            ausgabe[i][j] = eingabe[j + i * 16]
    return ausgabe

#Das eingegebene Array aufteilen und das PKCS#7 Padding anwenden
'''
PKCS#7: 
Beim PKCS#7 Padding wird die Anzahl der fehlenden Bytes eines Blocks bestimmt (bei einem vollen letzten Block sind es 16 Bytes), in die aufzufüllenden Bytes wird die Zahl der aufzufüllenden Bytes als Zahl gespeichert. Sind also vier Bytes eines Blocks nicht aufgefüllt, so werden die letzten vier Stellen mit der Zahl 4 gefüllt
'''
def array_aufteilen_pkcs7_padding(eingabe):
    länge = len(eingabe)
    ausgabe = np.zeros((math.ceil(länge/16) + (1 if länge%16 == 0 else 0), 16), dtype=np.uint8)
    for i in range(math.ceil(länge/16)):
        length = 16 if ((i + 1) * 16) <= länge else (länge % 16) 
        for j in range(length):
            ausgabe[i][j] = eingabe[j + i * 16]
    füll_byte = 16 if länge%16 == 0 else (16 - länge%16)
    for i in range(füll_byte):
        ausgabe[-1][15 - i] = füll_byte
    return ausgabe

#Wenn das PKCS#7 Padding verwendet wurde, kann dieses mit dieser Funktion wieder entfernt werden
def pkcs7_entfernen(eingabe):
    füll_byte = eingabe[-1]
    for i in range(füll_byte):
        eingabe = np.delete(eingabe, len(eingabe) - 1)
    return eingabe

#Diese Funktion kann eine Eingabe Datei in ein Array zum Verschlüsseln umwandeln
def datei_als_array(dateipfad):
    d = open(dateipfad, "rb")
    wörter = d.read()
    d.close()
    return list(wörter)

#Diese Funktion wandelt ein Array in eine Datei um, und speichert diese am angegebenen Dateipfad
def eingabe_als_datei(eingabe, dateipfad):
    d = open(dateipfad, "wb")
    zu_speichern = bytes(eingabe)
    d.write(zu_speichern)
    d.close()

#Einen hexadezimalen String beliebiger Länge in ein Array umwandeln
def hexstring_als_array(eingabe):
    ausgabe = np.array([], dtype=np.uint8)
    for i in range(int(len(eingabe)/2)):
        ausgabe = np.append(ausgabe, int(eingabe[i*2:i*2+2], 16))
    return ausgabe

#Ein beliebig langes Array in einen hexadezimalen String umwandeln
def array_als_hexstring(eingabe):
    ausgabe = ''
    for i in range(len(eingabe)):
        ausgabe = ausgabe + '{0:0{1}X}'.format(eingabe[i],2)
    return ausgabe

def array_als_bitstring(eingabe):
    ausgabe = ''
    for i in range(len(eingabe)):
        ausgabe = ausgabe + '{0:0{1}b}'.format(eingabe[i], 8)
    return ausgabe

def bitstring_als_array(eingabe):
    ausgabe = np.array([], dtype=np.uint8)
    for i in range(int(len(eingabe)/8)):
        ausgabe = np.append(ausgabe, int(eingabe[i*8:i*8+8], 2))
    return ausgabe

#Die Multiplikation zweiere Blöcke für den GCM Modus
def mul_block(b1, b2):
    bitb1 = array_als_bitstring(b1)
    z = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    v = b2
    for i in range(128):
        if bitb1[i] == '1':
            z = algorithm.add_round_key(z.copy(), v.copy())
        if bin(v[15])[-1] == '0':
            v = hexstring_als_array('{0:0{1}X}'.format((int(array_als_hexstring(v), 16) >> 1), 32))
        else:
            v = algorithm.add_round_key(hexstring_als_array('{0:0{1}X}'.format((int(array_als_hexstring(v), 16) >> 1), 32)), [0b11100001, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0])
    return z