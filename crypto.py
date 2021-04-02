#!/usr/bin/python
# -*- coding: utf-8 -*-
import string
import base64

flag_prefix = "flag"

#cipher      = "ch\\at]ZW+S$)6Q#k"                                          # sub
#cipher      = "gndk€rlqhmtkwwp}z"                                          # sub
#cipher      =  "&-#$-6$v"                                                  # xor
#cipher      = "uozt{zgyzhs_gvhg}"                                          # atbash
#cipher      = "synt{ebg13_grfg}"                                           # rot13
#cipher      = "MzkuM3gvMUAwnzuvn3cgozMlMTuvqzAenJchMUAeqzWenzEmLJW9"       # rot13
#cipher      = "7=28LC@Ecf0E6DEN"                                           # rot47
#cipher      = "ypau_kjg;\"g;\"ypau+"                                       # keyboard1
#cipher      = "ysqu ol lq1uxfpx3rxo5iol4ouxf"                              # keyboard2
#cipher      = "tnys{yfxygrylvgex}"                                         # atbash & sub
#cipher      = "}KccnYt!1NlPpu!zeE1{C+9pfrhLB_Fz~uGy4n"                     # rot13 & search_flag
#cipher      = "Èé¬ ÆòåóèÄïç¡ Ôèå æìáç éóº èêúãùäêúâêäãêëúëãõçéóäãèêùêóâäæò"# sub 128 | xor 128
cipher      = "mxWYntnZiVjMxEjY0kDOhZWZ4cjYxIGZwQmY2ATMxEzNlFjNl13X"       # reverse & base64
#cipher      = "ysqu{6y980e0101e8qq361977eqe06508q3rt}"                     # keyboard2

# 针对 flag 在开头的场景，将密文逐字节减去 "flag"，观察差值是否存在规律
def sub(cipher, print_info = "sub"):
    print("--------" + print_info + "--------")
    for i in range(len(flag_prefix)):
        print("%d " % abs(ord(cipher[i]) - ord(flag_prefix[i])), end = "")
    print("\r")

# 针对 flag 在中间的场景
def sub_bruteforce(cipher):
    for i in range(1, 255):
        cipher_sub = ""
        for j in range(len(cipher)):
            cipher_sub += chr(abs(ord(cipher[j]) - i))
        search_flag(cipher_sub, "sub{0} may get flag".format(i))

# 针对 flag 在开头的场景，将密文逐字节与 "flag" 异或，观察是否存在规律
def xor(cipher, print_info = "xor"):
    print("--------" + print_info + "--------")
    for i in range(len(flag_prefix)):
        print("%x " % (ord(cipher[i]) ^ ord(flag_prefix[i])), end = "")
    print("\r")

# 针对 flag 在中间的场景
def xor_bruteforce(cipher):
    for i in range(0, 255):
        cipher_xor = ""
        for j in range(len(cipher)):
            cipher_xor += chr(ord(cipher[j]) ^ i)
        search_flag(cipher_xor, "xor{0} may get flag".format(i))

# 26 个字母首尾互换
def atbash(cipher, print_info = ""):
    if ("" != print_info):
        print("--------" + print_info + "--------")
    atbash          = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba")
    cipher_atbash   = str.translate(cipher, atbash)
    return cipher_atbash

def rot13(cipher, print_info = ""):
    if ("" != print_info):
        print("--------" + print_info + "--------")
    rot13           = str.maketrans("ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz", "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")
    cipher_rot13    = str.translate(cipher, rot13)
    return cipher_rot13

def rot47(cipher, print_info = ""):
    if ("" != print_info):
        print("--------" + print_info + "--------")
    rot47           = str.maketrans("!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~", "PQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO")
    cipher_rot47    = str.translate(cipher, rot47)
    return cipher_rot47

def keyboard1(cipher, print_info = ""):
    if ("" != print_info):
        print("--------" + print_info + "--------")
    keyboard        = str.maketrans("qwertyuiopasdfghjkl;\"zxcvbnm+_", "\"<>pyfgcrlaoeuidhtns_;qjkxbm}{")
    cipher_keyboard = str.translate(cipher, keyboard)
    return cipher_keyboard

def keyboard2(cipher, print_info = ""):
    if ("" != print_info):
        print("--------" + print_info + "--------")
    keyboard        = str.maketrans("qwertyuiopasdfghjklzxcvbnm", "abcdefghijklmnopqrstuvwxyz")
    cipher_keyboard = str.translate(cipher, keyboard)
    return cipher_keyboard

def search_flag(new_cipher, print_info):
    for i in range(len(flag_prefix)):
        if (-1 == new_cipher.find(flag_prefix[i])):
            return
    print("--------" + print_info + "--------")

def reverse_base64(cipher, print_info):
    if ("" != print_info):
        print("--------" + print_info + "--------")
        reverse_cipher = cipher[::-1]
    try:
        print(base64.b64decode(reverse_cipher))
    except:
        print("base64 decode error")

def reverse_base32(cipher, print_info):
    if ("" != print_info):
        print("--------" + print_info + "--------")
    reverse_cipher = cipher[::-1]
    try:
        print(base64.b32decode(reverse_cipher))
    except:
        print("base32 decode error")

def reverse_base16(cipher, print_info):
    if ("" != print_info):
        print("--------" + print_info + "--------")
    reverse_cipher = cipher[::-1]
    try:
        print(base64.b16decode(reverse_cipher))
    except:
        print("base16 decode error")

if __name__ == '__main__':
    sub(cipher)
    xor(cipher)

    print(atbash(cipher, "atbash"))
    print(rot13(cipher, "rot13"))
    print(rot47(cipher, "rot47"))
    print(keyboard1(cipher, "keyboard1"))
    print(keyboard2(cipher, "keyboard2"))

    sub(atbash(cipher), "atbash & sub")
    sub(rot13(cipher), "rot13 & sub")
    sub(rot47(cipher), "rot47 & sub")
    sub(keyboard1(cipher), "keyboard1 & sub")
    sub(keyboard2(cipher), "keyboard2 & sub")

    xor(atbash(cipher), "atbash & xor")
    xor(rot13(cipher), "rot13 & xor")
    xor(rot47(cipher), "rot47 & xor")
    xor(keyboard1(cipher), "keyboard1 & xor")
    xor(keyboard2(cipher), "keyboard2 & xor")

    search_flag(atbash(cipher), "atbash may get flag")
    search_flag(rot13(cipher), "rot13 may get flag")
    search_flag(rot47(cipher), "rot47 may get flag")
    search_flag(keyboard1(cipher), "keyboard1 may get flag")
    search_flag(keyboard2(cipher), "keyboard2 may get flag")

    sub_bruteforce(cipher)
    xor_bruteforce(cipher)

    reverse_base64(cipher, "reverse & base64")
    reverse_base32(cipher, "reverse & base32")
    reverse_base16(cipher, "reverse & base16")
