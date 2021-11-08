'''
Kommandozeilenanwendung von AES

@Author: Yannic
Version: 05/10/2021
Python-Version: 3.7.9 64-Bit
'''

#Libraries und Imports:
#argparse für die Verwaltung von Kommandozeilenargumenten
import argparse
#numpy für schnellere Array Operationen und uint8
import numpy as np
#getpass für die Verdecktee Eingabe eines Schlüssels
import getpass
#Eigene Scripte:
import funcs
import modes
import algorithm

#Festlegung der Kommandozeilenargumente und welche Werte bei ihnen erwartet werden
parser = argparse.ArgumentParser(description='Ver- und Entschlüsseln mit dem Advanced Encryption Standard')
parser.add_argument('-m', '--mode', type=str, metavar='', required=True, help='Betriebsmodus')

keyoptions = parser.add_mutually_exclusive_group()
keyoptions.add_argument('-k', '--key', type=str, metavar='', help='Schlüssel')
keyoptions.add_argument('-hk', '--hex_key', type=str, metavar='', help='Schlüssel als Hexadezimalstring')
keyoptions.add_argument('-pw', '--password', action='store_true', help='Schlüssel verdeckt eingeben')
keyoptions.add_argument('-hpw', '--hex_password', action='store_true', help='Schlüssel verdeckt als Hexadezimalzahl eingeben')

ivoptions = parser.add_mutually_exclusive_group()
ivoptions.add_argument('-iv', '--initialization_vector', metavar='', type=str, help='Initialisierungsvektor für CBC etc.')
ivoptions.add_argument('-hiv', '--hex_initialization_vector', metavar='', type=str, help='Hexadezimaler Initialisierungsvektor')

parser.add_argument('-p', '--padding', metavar='', type=str, help='Verwendete Auffüllmethode')

parser.add_argument('-o', '--output', metavar='', type=str, help='Ausgabefile')

output_type = parser.add_mutually_exclusive_group()
output_type.add_argument('-H', '--hex', action='store_true', help='Ausgabe von Text als Hexadezimal-Array')
output_type.add_argument('-s', '--suppress_output', action='store_true', help='Keine Ausgabe im Terminal')

dec_or_enc = parser.add_mutually_exclusive_group()
dec_or_enc.add_argument('-d', '--decrypt', action='store_true', help='Entschlüsseln')
dec_or_enc.add_argument('-e', '--encrypt', action='store_true', help='Verschlüsseln')

input_method = parser.add_mutually_exclusive_group()
input_method.add_argument('-f', '--file', type=str, metavar='', help='Eingabedatei')
input_method.add_argument('-t', '--text', type=str, metavar='', help='Klartext/Geheimtext')
input_method.add_argument('-ht', '--hex_text', type=str, metavar='', help='Eingabe Klartext/Geheimtext als hexadezimaler String')

args = parser.parse_args()

#main-Funktion welche aufgerufen wird, wenn das Programm benutzt wird
def main():
    global daten
    global iv
    global output

    #Überprüfen, welche Art von Schlüssel benutzt wird, danach die Schlüsselerweiterung mit den passenden Parametern auf
    if args.key and ((len(args.key) == 16) or (len(args.key) == 24) or (len(args.key) == 32)):
        keys = algorithm.key_expansion(funcs.string_in_array_umwandeln(args.key), 0)
    elif args.hex_key and ((len(args.hex_key) == 32) or (len(args.hex_key) == 48) or (len(args.hex_key) == 64)):
        keys = algorithm.key_expansion(funcs.hexstring_als_array(args.hex_key), 0)
    elif args.password:
        pw = getpass.getpass("Passwort: ")
        keys = algorithm.key_expansion(funcs.string_in_array_umwandeln(pw), 0)
    elif args.hex_password:
        pw = getpass.getpass("Passwort: ")
        keys = algorithm.key_expansion(funcs.hexstring_als_array(pw), 0)
    else:
        print("Invalid key length! Please try again.")
        exit()

    runden = algorithm.get_anzahl_runden()
    #Überprüfen ob ein Initialisierungsvektor angegeben wurde, und wenn von welcher Art
    if args.initialization_vector:
        iv = funcs.string_in_array_umwandeln(args.initialization_vector)
    elif args.hex_initialization_vector:
        iv = funcs.hexstring_als_array(args.hex_initialization_vector)

    #Wenn der Initialisierungsvektor nicht die richtige größe hat wird das Programm abgebrochen
    if (args.initialization_vector or args.hex_initialization_vector) and (len(iv) != 16):
        print("Invalid IV length!")
        exit()

    #Wenn die Flagge -e angegeben wurde, dann werden die angegebenen Daten verschlüsselt
    if args.encrypt:
        #Daten mit dem Richtigen Padding auffüllen und in ein Array aufteilen
        if (args.padding and args.padding.lower() == 'zeros') or (args.mode.lower() == 'ctr' or args.mode.lower() == 'cfb' or args.mode.lower() == 'ofb'):
            if args.text:
                daten = funcs.string_in_array_umwandeln(args.text)
            elif args.hex_text:
                daten = funcs.hexstring_als_array(args.hex_text)
            elif args.file:
                daten = funcs.datei_als_array(args.file)
            daten = funcs.array_aufteilen_zero_padding(daten)
        else:
            if args.text:
                daten = funcs.string_in_array_umwandeln(args.text)
            elif args.hex_text:
                daten = funcs.hexstring_als_array(args.hex_text)
            elif args.file:
                daten = funcs.datei_als_array(args.file)
            daten = funcs.array_aufteilen_pkcs7_padding(daten)

        #Bestimmen des Betriebsmodus
        if args.mode.lower() == 'ecb':
            output = modes.enc_ecb(daten, keys, runden)
        elif args.mode.lower() == 'cbc':
            output = modes.enc_cbc(daten, keys, runden, iv)
        elif args.mode.lower() == 'ctr':
            output = modes.ctr(daten, keys, runden, iv)
        elif args.mode.lower() == 'cfb':
            output = modes.enc_cfb(daten, keys, runden, iv)
        elif args.mode.lower() == 'ofb':
            output = modes.ofb(daten, keys, runden, iv)
    
    #Wenn die Flagge -d angegeben wurde, dann werden die Daten entschlüsselt
    elif args.decrypt:
        #Angegebenen Daten in ein Array umwandeln
        if args.text:
            daten = funcs.string_in_array_umwandeln(args.text)
        elif args.hex_text:
            daten = funcs.hexstring_als_array(args.hex_text)
        elif args.file:
            daten = funcs.datei_als_array(args.file)
        daten = funcs.array_aufteilen_zero_padding(daten)

        #Betriebsmodus bestimmen
        if args.mode.lower() == 'ecb':
            output = modes.dec_ecb(daten, keys, runden)
        elif args.mode.lower() == 'cbc':
            output = modes.dec_cbc(daten, keys, runden, iv)
        elif args.mode.lower() == 'ctr':
            output = modes.ctr(daten, keys, runden, iv)
        elif args.mode.lower() == 'cfb':
            output = modes.dec_cfb(daten, keys, runden, iv)
        elif args.mode.lower() == 'ofb':
            output = modes.ofb(daten, keys, runden, iv)

        #Wenn nötig das Padding entfernen
        if (args.padding and args.padding.lower() == 'zeros') or (args.mode.lower() == 'ctr' or args.mode.lower() == 'cfb' or args.mode.lower() == 'ofb'):
            pass
        else:
            output = funcs.pkcs7_entfernen(output)
    
    #Wenn eine Ausgabedatei angegeben wurde, so werden die verschlüsselten Daten in dieser gespeichert
    if args.output:
        funcs.eingabe_als_datei(output, args.output)

    #Bestimmen ob die Ausgabe als Hexadezimalarray, als Text ausgegeben oder unterdrückt werden soll
    if args.hex:
        #np.set_printoptions(formatter={'int':hex})
        print(funcs.array_als_hexstring(output))
    elif args.suppress_output:
        print("Output suppressed!")
    else:
        print(funcs.array_in_string_umwandeln(output))

if __name__ == '__main__':
    main()