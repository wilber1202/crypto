#!/usr/bin/python
# -*- coding: utf-8 -*-
import uu
import math
import gmpy2
import string
import base36
import base58
import base64
import base91
import binascii
from codecs import decode, encode

flag_prefix = "flag"
#flag_prefix = "TUCTF"

#cipher      = "ch\\at]ZW+S$)6Q#k"                                          # sub
#cipher      = "gndk€rlqhmtkwwp}z"                                          # sub
#cipher      = "afZ_r9VYfScOeO_UL^RWUc"                                     # sub
#cipher      = "&-#$-6$v"                                                   # xor
#cipher      = "cbtcqLUBChERV[[Nh@_X^D]X_YPV[CJ"                            # xor55 - TUCTF
#cipher      = "uozt{zgyzhs_gvhg}"                                          # atbash
#cipher      = "synt{ebg13_grfg}"                                           # rot13
#cipher      = "MzkuM3gvMUAwnzuvn3cgozMlMTuvqzAenJchMUAeqzWenzEmLJW9"       # rot13 + base64
#cipher      = "7=28LC@Ecf0E6DEN"                                           # rot47
#cipher      = "ypau_kjg;\"g;\"ypau+"                                       # keyboard1
#cipher      = "ysqu ol lq1uxfpx3rxo5iol4ouxf"                              # keyboard2
#cipher      = "ysqu{6y980e0101e8qq361977eqe06508q3rt}"                     # keyboard2
#cipher      = "tnys{yfxygrylvgex}"                                         # atbash & sub
#cipher      = "}KccnYt!1NlPpu!zeE1{C+9pfrhLB_Fz~uGy4n"                     # rot13 & search_flag
#cipher      = "Èé¬ ÆòåóèÄïç¡ Ôèå æìáç éóº èêúãùäêúâêäãêëúëãõçéóäãèêùêóâäæò"# sub 128 | xor 128
#cipher      = "mxWYntnZiVjMxEjY0kDOhZWZ4cjYxIGZwQmY2ATMxEzNlFjNl13X"       # reverse & base64
#cipher      = "zMXHz3T3AwXIzxj9"                                           # swapcase & base64
#cipher      = "pvsy{vvimdvnvtigaomcweknptvhceycncbvv}"                     # odd even decode
#cipher      = "89FQA9WMD<V1A<V1S83DY.#<W3$Q,2TM]"                          # uuencode
#cipher      = "#@~^RAAAAA==\ko$K6r m9v1+&FcT0O%[0Rl4l^!m!cmX[F+c+cE~*3cT,+SJ6VCLr)hj/Mk2Yc5!kOtRMAAA==^#~@"    # vbs
#cipher      = "663686e6de96fa32f66ea6fa92c2cafacea6c6ae4e962e9e84be"       # reverse_binary
#cipher      = "8nCDq36slSH4DycVQo9XhR4aF3u3x8PkP8gkb5rw5HtpUf3jI2t3"       # base62
#cipher      = "vbkq{Ty_Iye_Udyg_Gxkj_sc_Ytt_Olod_Mkockh?}"                 # odd even decode
#cipher      = "ysqu{r4_s4g_4g_so_u3o}"                                     # keyboard2
#cipher      = "Z25ka4BJeYF5fjtzf29/eIpxR4J5dVp5fk98jmCHj4hUlIJVmIWNnZeYpKk=" # base64 & sub
cipher      = "EwzB3KQcFGnVmxPsPK8xBX9GMgR7RUFJcdXLtxKXM"                  # reverse & base58

# 针对 flag 在开头的场景，将密文逐字节减去 "flag"，观察差值是否存在规律
def sub(cipher, print_info = "sub"):
    print("--------" + print_info.center(30) + "--------: ", end = "")
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
    print("--------" + print_info.center(30) + "--------: ", end = "")
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
        print("--------" + print_info.center(30) + "--------: ", end = "")
    atbash          = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba")
    cipher_atbash   = str.translate(cipher, atbash)
    return cipher_atbash

def rot13(cipher, print_info = ""):
    if ("" != print_info):
        print("--------" + print_info.center(30) + "--------: ", end = "")
    rot13           = str.maketrans("ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz", "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")
    cipher_rot13    = str.translate(cipher, rot13)
    return cipher_rot13

def rot47(cipher, print_info = ""):
    if ("" != print_info):
        print("--------" + print_info.center(30) + "--------: ", end = "")
    rot47           = str.maketrans("!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~", "PQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO")
    cipher_rot47    = str.translate(cipher, rot47)
    return cipher_rot47

def keyboard1(cipher, print_info = ""):
    if ("" != print_info):
        print("--------" + print_info.center(30) + "--------: ", end = "")
    keyboard        = str.maketrans("qwertyuiopasdfghjkl;\"zxcvbnm+_", "\"<>pyfgcrlaoeuidhtns_;qjkxbm}{")
    cipher_keyboard = str.translate(cipher, keyboard)
    return cipher_keyboard

def keyboard2(cipher, print_info = ""):
    if ("" != print_info):
        print("--------" + print_info.center(30) + "--------: ", end = "")
    keyboard        = str.maketrans("qwertyuiopasdfghjklzxcvbnm", "abcdefghijklmnopqrstuvwxyz")
    cipher_keyboard = str.translate(cipher, keyboard)
    return cipher_keyboard

def search_flag(new_cipher, print_info):
    for i in range(len(flag_prefix)):
        if (-1 == new_cipher.find(flag_prefix[i])):
            return
    print("--------" + print_info.center(30) + "--------: ", end = "")
    print(new_cipher)

def base91_decode(cipher, print_info = ""):
    if ("" != print_info):
        print("--------" + print_info.center(30) + "--------: ", end = "")
    try:
        print(base91.decode(cipher))
    except:
        print("base91 decode error")

def base85_decode(cipher, print_info = ""):
    if ("" != print_info):
        print("--------" + print_info.center(30) + "--------: ", end = "")
    try:
        print(base64.b85decode(cipher))
    except:
        print("base85 decode error")

def base64_decode(cipher, print_info = ""):
    if ("" != print_info):
        print("--------" + print_info.center(30) + "--------: ", end = "")
    try:
        print(base64.b64decode(cipher))
    except:
        print("base64 decode error")

def base62_decode(cipher, print_info = ""):
    if ("" != print_info):
        print("--------" + print_info.center(30) + "--------: ", end = "")
    try:
        result = ''
        strlen = len(cipher)
        for i in range(0, strlen, 11):
            x       = slice(i, i + 11)
            chunk   = str(cipher)[x]
            outlen  = math.floor((len(chunk) * 6) / 8)
            number  = chunk.lstrip('0')
            if ('' == number):
                number = '0'
            y       = gmpy2.digits(gmpy2.mpz(number, 62), 16)
            pad     = y.zfill(outlen * 2)
            result  += binascii.unhexlify(pad.encode()).decode()
        print(result)
    except:
        print("base62 decode error")

def base58_decode(cipher, print_info = ""):
    if ("" != print_info):
        print("--------" + print_info.center(30) + "--------: ", end = "")
    try:
        print(base58.b58decode(cipher))
    except:
        print("base58 decode error")

def base32_decode(cipher, print_info = ""):
    if ("" != print_info):
        print("--------" + print_info.center(30) + "--------: ", end = "")
    try:
        print(base64.b32decode(cipher))
    except:
        print("base32 decode error")

def base16_decode(cipher, print_info = ""):
    if ("" != print_info):
        print("--------" + print_info.center(30) + "--------: ", end = "")
    try:
        print(base64.b16decode(reverse_cipher))
    except:
        print("base16 decode error")

def base_decode(cipher):
    base91_decode(cipher, "base91 decode")
    base85_decode(cipher, "base85 decode")
    base64_decode(cipher, "base64 decode")
    base62_decode(cipher, "base62 decode")
    base58_decode(cipher, "base58 decode")
    base32_decode(cipher, "base32 decode")
    base16_decode(cipher, "base16 decode")

def reverse_base_decode(cipher):
    reverse_cipher = cipher[::-1]
    base91_decode(reverse_cipher, "reverse base91 decode")
    base85_decode(reverse_cipher, "reverse base85 decode")
    base64_decode(reverse_cipher, "reverse base64 decode")
    base62_decode(reverse_cipher, "reverse base62 decode")
    base58_decode(reverse_cipher, "reverse base58 decode")
    base32_decode(reverse_cipher, "reverse base32 decode")
    base16_decode(reverse_cipher, "reverse base16 decode")

def swap_base_decode(cipher):
    swapcase_cipher = cipher.swapcase()
    base91_decode(swapcase_cipher, "swap base91 decode")
    base85_decode(swapcase_cipher, "swap base85 decode")
    base64_decode(swapcase_cipher, "swap base64 decode")
    base62_decode(swapcase_cipher, "swap base62 decode")
    base58_decode(swapcase_cipher, "swap base58 decode")
    base32_decode(swapcase_cipher, "swap base32 decode")
    base16_decode(swapcase_cipher, "swap base16 decode")

# 在单字节范围内逆序，例如 663686e6 转换成 6663686e
def reverse_binary(cipher, print_info):
    if ("" != print_info):
        print("--------" + print_info.center(30) + "--------: ", end = "")
    try:
        unhex_cipher    = binascii.unhexlify(cipher)
        result          = ""
        for c in unhex_cipher:
            bin_cipher      = bin(c)[2:].zfill(8)
            reverse_cipher  = int(bin_cipher[::-1], 2)
            result          += chr(reverse_cipher)
        print(result)
    except:
        print("reverse binary error")

# uudecode，解码前必须添加前缀和后缀，且参数是 byte 类型
# https://stackoverflow.com/questions/48841673/python-how-to-decode-uuencoded-text
def uu_decode(cipher, print_info):
    if ("" != print_info):
        print("--------" + print_info.center(30) + "--------: ", end = "")
    try:
        cipher_trans = "begin 666 <data>\n" + cipher + "\n \nend\n"
        print(decode(cipher_trans.encode(), 'uu'))
    except:
        print("uudecode error")

def vbs_decode(cipher, print_info):
    if ("" != print_info):
        print("--------" + print_info.center(30) + "--------: ", end = "")
    if ("#@~" == cipher[0:3]) and ("#~@" == cipher[-3:]):
        print("VBS cipher")
    else:
        print("Not VBS cipher")

# 密文的 ASCII 码如果是偶数，减去一个固定的数值，如果是奇数，减去另外一个固定的数值
def odd_even_decode(cipher, print_info):
    if ("" != print_info):
        print("--------" + print_info.center(30) + "--------: ", end = "")
    diff = [(ord(cipher[i]) - ord(flag_prefix[i])) % 26 for i in range(len(flag_prefix))]
    if ((diff[0] != diff[1]) or (diff[2] != diff[3])):
        print(diff[0], diff[1], diff[2], diff[3])
        return []
    even    = diff[0]
    odd     = diff[2]
    result  = ""
    for c in cipher:
        if (ord(c) >= ord('a')) and (ord(c) <= ord('z')):
            if (0 == ord(c) % 2):
                result += chr((ord(c) - ord('a') - even) % 26 + ord('a'))
            else:
                result += chr((ord(c) - ord('a') - odd) % 26 + ord('a'))
        elif (ord(c) >= ord('A')) and (ord(c) <= ord('Z')):
            if (0 == ord(c) % 2):
                result += chr((ord(c) - ord('A') - even) % 26 + ord('A'))
            else:
                result += chr((ord(c) - ord('A') - odd) % 26 + ord('A'))
        else:
            result += c
    print(result)

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

    base_decode(cipher)
    reverse_base_decode(cipher)
    swap_base_decode(cipher)

    reverse_binary(cipher, "to binary, then reverse")

    uu_decode(cipher, "uu decode")
    vbs_decode(cipher, "vbs decode")
    odd_even_decode(cipher, "odd even decode")
