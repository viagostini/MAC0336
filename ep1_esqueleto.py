# coding: utf-8

"""
    Esqueleto para o EP1 de Cripto 2020
    Prof. Routo Terada
    Monitor: Thales Paiva

    Exemplo de como rodar o arquivo e saída do programa:
    [~/cripto-2020/ep1]$ sage ep1_esqueleto.py documento.txt
    O Hash SHA512 do arquivo documento.txt é
    dd8996d0f9f8c17056ab3314105ca4043ef729adf8b0f5f84e0d71ef8e51765cfa58741df01aaa5ae5642c54ecf47b2de02140f95956d3d6370e2ade18ef7a13
    O inteiro correspondente ao hash para uso no ElGamal é
    11602858124117136456103271775114122754696733789413816382276456553852239770973923409586227117425499556575579222816159862027314152111415107121278401054210579
    A distância de Hamming entre 0x4123 e 0x3189 é
    7
"""

from sage.all import *
from sage.crypto.util import ascii_to_bin

import os
import sys
import string
import random
import hashlib
from binascii import hexlify, unhexlify


# Parâmetros públicos p e g
# PRIME = 3329499024484696430955445194464218832905973351121497617435753366182222251575714808510036328892050841
# GENERATOR = 17
PRIME_A = 10556903207286767181741614405391493132158714643702501887676502954427109116849995896933852122361081109139592877832545731729513028521947294977454763046753869
GENERATOR_A = 2

PRIME_B = 12637605196018713070344024070559107270222392636771841277241890397335519948617721264222435838004088482001906984571037477049776352675510413355478433564714789
GENERATOR_B = 6

def elgamal_keygen(prime, generator):
    Zp = Integers(prime)

    secret_key = randint(1, prime-2)
    public_key = Zp(generator) ** secret_key

    return (prime, generator, secret_key, public_key)


def random_coprime(n):
    '''
    Devolve um número x coprimo em relação a n tal que gcd(x, n) = 1.
    '''
    x = 0

    while gcd(x, n) != 1:
        x = randint(2, n-1)
    
    return x

def elgamal_sign(message, prime, generator, secret_key):
    Zp = Integers(prime)
    Zp1 = Integers(prime-1)

    k = random_coprime(prime-1)

    # mod p
    y = Zp(generator) ** k
    
    # mod p-1
    message = int(message, 16)
    z = (message - (secret_key * Zp1(y))) * Zp1(k) ** (-1)

    return (y, z)


def elgamal_verify(signature, message, prime, generator, public_key):
    y, z = signature

    Zp = Integers(prime)

    message = int(message, 16)

    if 0 < int(y) < prime:
        lhs = Zp(generator) ** message
        rhs = (Zp(public_key) ** y) * (y ** z)

        return (lhs == rhs, lhs, rhs)

    # se y estiver fora do intervalo [1, p-1], não precisa calcular
    return (False, None, None)

def KEM_calculate_u(prime, generator):
    Zp = Integers(prime)

    secret_key = randint(2, prime-2)
    public_key = Zp(generator) ** secret_key

    r = randint(0, prime-2)
    u = Zp(generator) ** r

    return (r, u, secret_key, public_key)

def KEM_get_key(r, u, prime, secret_key, public_key):
    Zp = Integers(prime)
    
    K = (Zp(u) ** secret_key) * (Zp(public_key) ** r)

    return K

def get_binary_representation_512_bits_of_hex(h):
    '''
    Recebe uma string h representando um hexadecimal.
    Devolve a representação binária de h com EXATAMENTE 512 bits
    '''

    bin_h = bin(int(h, 16))[2:]  # [2:] Tira o 0b da frente
    bin_h_512bits = '0' * (512 - len(bin_h)) + bin_h

    return bin_h_512bits

def hamming_int(a, b):
    count = 0
    xor = int(a)^int(b)
    
    while xor:
        count += 1
        xor &= (xor - 1)
    return count

def hamming_distance_with_hex_strings(h1, h2):
    """
    Calcula a distância de hamming entre dois hashes em STRINGS representando
    hexadecimais
    """

    #bin_h1 = get_binary_representation_512_bits_of_hex(h1)
    #bin_h2 = get_binary_representation_512_bits_of_hex(h2)

    bin_h1 = ascii_to_bin(h1)
    bin_h2 = ascii_to_bin(h2)

    distance = 0
    for x1, x2 in zip(bin_h1, bin_h2):
        if x1 != x2:
            distance += 1
    return distance


def sha512_file(filepath):
    BLOCK_SIZE = 65536  # = 64Kb

    file_hash = hashlib.sha512()
    with open(filepath, 'rb') as f:
        fb = f.read(BLOCK_SIZE)
        while len(fb) > 0:
            file_hash.update(fb)
            fb = f.read(BLOCK_SIZE)

    return file_hash.hexdigest()

def read_file(filepath):
    file = open(filepath, 'r')
    text = file.read()
    file.close()
    return text

def modify_file(file):
    new_file = list(file)
    
    idx = randint(0, len(new_file))
    new_file[idx] = random.choice(string.ascii_letters)
    
    return str(new_file)

def main():
    """
    Função principal que ordena as chamadas de funções para realizar o que foi
    pedido no EP.
    """
    if len(sys.argv) != 2:
        print('Uso: %s <documento>' % sys.argv[0])
        sys.exit(1)

    # Abaixo mostro como calcular o hash de um arquivo:
    # filepath = sys.argv[1]
    # filehash = sha512_file(filepath)
    
    # print('O Hash SHA512 do arquivo %s é' % (filepath))
    # print(filehash)

    # print('O inteiro correspondente ao hash para uso no ElGamal é')
    # print(int(filehash, 16))

    # print('A distância de Hamming entre 0x4123 e 0x3189 é')
    # print(hamming_distance_with_hex_strings('0x4123', '0x3189'))



    # 1.
    print('\n# ---------- Item 1. ---------- #')
    print('\n Chave Alice:')
    pA, gA, SA, TA = elgamal_keygen(PRIME_A, GENERATOR_A)
    print(pA, gA, SA, TA)

    # 1.
    print('\n Chave Beto:')
    pB, gB, SB, TB = elgamal_keygen(PRIME_B, GENERATOR_B)
    print(pB, gB, SB, TB)
   
    # 2
    print('\n# ---------- Item 2. ---------- #')
    nusp = 4367487
    num_bytes = int(1e5)
    random_bytes_hex = hexlify(os.urandom(num_bytes))

    print('\n Primeiros 100 caracteres de documento1 (em hexadecimal):')
    documento1 = str(nusp) + random_bytes_hex
    print(documento1[:100])


    # 3
    print('\n# ---------- Item 3. ---------- #')
    print('\n Primeiros 100 caracteres de documento2 (em hexadecimal):')
    documento2 = str(nusp + 1) + random_bytes_hex
    print(documento2[:100])

    # 4
    print('\n# ---------- Item 4. ---------- #')
    print('\n Hash de documento1 (hash1)')
    hash1 = hashlib.sha512(documento1).hexdigest()
    print(hash1)

    print('\n Hash de documento2 (hash2)')
    hash2 = hashlib.sha512(documento2).hexdigest()
    print(hash2)
    
    # 5
    print('\n# ---------- Item 5. ---------- #')
    print('\n Assinatura de hash1')
    assinaturaHash1 = elgamal_sign(hash1, pA, gA, SA)
    print(assinaturaHash1)

    print('\n Assinatura de hash2')
    assinaturaHash2 = elgamal_sign(hash1, pA, gA, SA)
    print(assinaturaHash2)

    # 6
    print('\n# ---------- Item 6. ---------- #')
    print('\n Distancia de Hamming de assinaturaHash1 e assinaturaHash2')
    y1, z1 = assinaturaHash1
    y2, z2 = assinaturaHash2
    hamming_y = hamming_int(y1, y2)
    hamming_z = hamming_int(z1, z2)
    print(hamming_y + hamming_z)

    # 7
    print('\n# ---------- Item 7. ---------- #')
    print('\n Verificação de assinaturaHash1 sobre hash1')
    print(elgamal_verify(assinaturaHash1, hash1, pA, gA, TA))

    # 8
    print('\n# ---------- Item 8. ---------- #')
    print('\n Verificação de assinaturaHash1 sobre hash2')
    print(elgamal_verify(assinaturaHash1, hash2, pA, gA, TA))

    # 9.1
    print('\n# ---------- Item 9.1 ---------- #')
    print('\n Hash do Arquivo arq1.txt (hashA)')
    hashA = sha512_file('arq1.txt')
    print(hashA)
    
    # 9.2
    print('\n# ---------- Item 9.2 ---------- #')
    print('\n 9.2 Assinatura de hashA')
    assinaturaHashA = elgamal_sign(hashA, pA, gA, SA)
    print(assinaturaHashA)
    
    # 9.3
    print('\n# ---------- Item 9.3 ---------- #')
    print('\n Verificação de assinaturaHashA sobre hashA')
    print(elgamal_verify(assinaturaHash1, hash1, pA, gA, TA))

    # 9.4
    #print('\n# ---------- Item 9.4 ---------- #')
    arq1 = read_file('arq1.txt')
    arq1mod = modify_file(arq1)

    # 9.5
    print('\n# ---------- Item 9.5 ---------- #')
    print('\n Hash de arq1.txt modificado (hashAmod)')
    hashAmod = hashlib.sha512(arq1mod).hexdigest()
    print(hashAmod)

    # 9.5
    print('\n Assinatura de hashAmod')
    assinaturaHashAmod = elgamal_sign(hashAmod, pA, gA, SA)
    print(assinaturaHashAmod)

    # 9.6
    print('\n# ---------- Item 9.6 ---------- #')
    print('\n Distancia de Hamming de assinaturaHash1 e assinaturaHash2')
    y1, z1 = assinaturaHashA
    y2, z2 = assinaturaHashAmod
    hamming_y = hamming_int(y1, y2)
    hamming_z = hamming_int(z1, z2)
    print(hamming_y + hamming_z)

    # 10.a
    print('\n# ---------- Item 10.1 ---------- #')
    arq1mod = read_file('arq1.txt') + str(y1) + str(z1)
    print(arq1mod)

    # 10.b
    print('\n# ---------- Item 10.2 ---------- #')
    print('\n Hash de arq1.txt | assinaturaHashA')
    hash2 = hashlib.sha512(arq1mod).hexdigest()
    print(hash2)

    # 10.c
    print('\n# ---------- Item 10.3 ---------- #')
    hash1 = hashlib.sha512(arq1).hexdigest()
    assinaturaHashA = elgamal_sign(hash1, pA, gA, SA)
    assinaturaHashB = elgamal_sign(hash2, pB, gB, SB)
    print(assinaturaHashB)

    # 10.d
    print('\n# ---------- Item 10.4 ---------- #')
    print(elgamal_verify(assinaturaHashB, hash2, pB, gB, TB))

    # 11
    print('\n# ---------- Item 11 ---------- #')
    print('\n ua, ub:')
    ra, ua, SA, TA = KEM_calculate_u(pA, gA)
    rb, ub, SB, TB = KEM_calculate_u(pA, gA)
    print(ua, ub)
    print('\n ka, kb:')
    ka = KEM_get_key(ra, ub, pA, SA, TB)
    kb = KEM_get_key(rb, ua, pA, SB, TA)
    ka = hashlib.sha512(str(ka)).hexdigest()
    print(ka, kb)

    return

    print('\n# ---------- Item 12 ---------- #')
    print(hamming_int(ka, kb))

    #pub, sec = elgamal_keygen()
    #signature = elgamal_sign(filehash, sec)
    #print(elgamal_verify(signature, filehash, pub))

if __name__ == '__main__':
    main()

