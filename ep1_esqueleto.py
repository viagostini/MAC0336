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

# para texto em negrito
class color:
    BOLD = '\033[1m'
    END = '\033[0m'

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

def to_hex(*args):
    return (hashlib.sha512(str(key)).hexdigest() for key in args)

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
    title = ' Item 1 - Geração de chaves de Alice e Beto '
    print('\n' + title.center(100, '-') + '\n')

    print(' Chave Alice:\n')
    
    pA, gA, SA, TA = elgamal_keygen(PRIME_A, GENERATOR_A)
    
    print(
        "prime: {}\n\n"        \
        "generator: {}\n\n"    \
        "secret_key: {}\n\n"   \
        "public_key: {}"
    .format(*to_hex(pA, gA, SA, TA)))

    print('\n----------------')

    # 1.
    print('\n ' 'Chave Beto:\n')
    
    pB, gB, SB, TB = elgamal_keygen(PRIME_B, GENERATOR_B)
    
    print(
        "prime: {}\n\n"        \
        "generator: {}\n\n"  \
        "secret_key: {}\n\n" \
        "public_key: {}\n\n"
    .format(*to_hex(pB, gB, SB, TB)))
   
    # 2
    title = ' Item 2 - Primeiros 100 caracteres de documento1 (em hexadecimal) '
    print('\n' + title.center(100, '-') + '\n')
    nusp = 4367487
    num_bytes = int(1e5)
    random_bytes_hex = hexlify(os.urandom(num_bytes))

    #print('\n Primeiros 100 caracteres de documento1 (em hexadecimal):')
    documento1 = str(nusp) + random_bytes_hex
    print(documento1[:100] + '\n\n')


    # 3
    title = ' Item 3 - Primeiros 100 caracteres de documento2 (em hexadecimal) '
    print('\n' + title.center(100, '-') + '\n')

    #print('\n\n Primeiros 100 caracteres de documento2 (em hexadecimal):')
    documento2 = str(nusp + 1) + random_bytes_hex
    print(documento2[:100] + '\n\n')

    # 4
    title = ' Item 4 - Hash de documento1 e documento2 '
    print('\n' + title.center(100, '-') + '\n')

    print(' Hash de documento1 (hash1)')
    hash1 = hashlib.sha512(documento1).hexdigest()
    print(hash1 + '\n\n')

    print(' Hash de documento2 (hash2)')
    hash2 = hashlib.sha512(documento2).hexdigest()
    print(hash2 + '\n\n')
    
    # 5
    title = ' Item 5 - Assinatura de hash1 e hash2 '
    print('\n' + title.center(100, '-') + '\n')

    print(' Assinatura de hash1')
    assinaturaHash1 = elgamal_sign(hash1, pA, gA, SA)
    print("y: {}\n"  "z: {}\n".format(*to_hex(*assinaturaHash1)))

    print('\n Assinatura de hash2')
    assinaturaHash2 = elgamal_sign(hash1, pA, gA, SA)
    print("y: {}\n"  "z: {}\n".format(*to_hex(*assinaturaHash2)))

    # 6
    title = ' Item 6 - Distância de Hamming de assinaturaHash1 e assinaturaHash2 '
    print('\n' + title.center(100, '-') + '\n')
    
    y1, z1 = assinaturaHash1
    y2, z2 = assinaturaHash2
    hamming_y = hamming_int(y1, y2)
    hamming_z = hamming_int(z1, z2)
    print(str(hamming_y + hamming_z) + '\n')

    # 7
    title = ' Item 7 - Verificação de assinaturaHash1 sobre hash1 '
    print('\n' + title.center(100, '-') + '\n')
    
    verify = elgamal_verify(assinaturaHash1, hash1, pA, gA, TA)
    print(
        "assinatura válida?: {}\n\n"        \
        "lado esquerdo: {}\n\n"  \
        "lado direito: {}\n\n"
    .format(verify[0], *to_hex(*verify[1:])))

    # 8
    title = ' Item 8 - Verificação de assinaturaHash1 sobre hash2 '
    print('\n' + title.center(100, '-') + '\n')
    
    verify = elgamal_verify(assinaturaHash1, hash2, pA, gA, TA)
    print(
        "assinatura válida?: {}\n\n"        \
        "lado esquerdo: {}\n\n"  \
        "lado direito: {}\n\n"
    .format(verify[0], *to_hex(*verify[1:])))

    # 9.1
    title = ' Item 9.1 - Hash do Arquivo arq1.txt (hashA) '
    print('\n' + title.center(100, '-') + '\n')

    hashA = sha512_file('arq1.txt')
    print(hashA + '\n\n')
    
    # 9.2
    title = ' Item 9.2 - Assinatura de hashA '
    print('\n' + title.center(100, '-') + '\n')
    assinaturaHashA = elgamal_sign(hashA, pA, gA, SA)
    print("y: {}\n\nz: {}\n\n".format(*to_hex(*assinaturaHashA)))
    
    # 9.3
    title = ' Item 9.3 - Verificação de assinaturaHAshA sobre hashA '
    print('\n' + title.center(100, '-') + '\n')

    verify = elgamal_verify(assinaturaHashA, hashA, pA, gA, TA)
    print(
        "assinatura válida?: {}\n\n"        \
        "lado esquerdo: {}\n\n"  \
        "lado direito: {}\n\n"
    .format(verify[0], *to_hex(*verify[1:])))

    # 9.4
    # ---------- Item 9.4 ----------
    arq1 = read_file('arq1.txt')
    arq1mod = modify_file(arq1)

    # 9.5
    title = ' Item 9.5 - Criação e assinatura de arq1.txt modificado '
    print('\n' + title.center(100, '-') + '\n')

    print(' Hash de arq1.txt modificado')
    hashAmod = hashlib.sha512(arq1mod).hexdigest()
    print(hashAmod + '\n')

    print('\n Assinatura de hashAmod')
    assinaturaHashAmod = elgamal_sign(hashAmod, pA, gA, SA)
    print("y: {}\n\nz: {}\n\n".format(*to_hex(*assinaturaHashAmod)))


    # 9.6
    title = ' Item 9.6 - Distancia de Hamming de assinaturaHash1 e assinaturaHash2 '
    print('\n' + title.center(100, '-') + '\n')

    y1, z1 = assinaturaHashA
    y2, z2 = assinaturaHashAmod
    hamming_y = hamming_int(y1, y2)
    hamming_z = hamming_int(z1, z2)
    print(str(hamming_y + hamming_z) + '\n')

    # 10.a
    #print('\n\n\n\n# ---------- Item 10.1 ---------- #')
    arq2 = read_file('arq1.txt') + str(y1) + str(z1)
    #print(arq2)

    # 10.b
    title = ' Item 10.2 - Hash de arq2 <- arq1 | assinaturaHashA '
    print('\n' + title.center(100, '-') + '\n')

    hash2 = hashlib.sha512(arq2).hexdigest()
    print(hash2 + '\n\n')

    # 10.c
    title = ' Item 10.3 - Assinatura de Beto sobre arq2 '
    print('\n' + title.center(100, '-') + '\n')

    hash1 = hashlib.sha512(arq1).hexdigest()
    #assinaturaHashA = elgamal_sign(hash1, pA, gA, SA)
    assinaturaHashB = elgamal_sign(hash2, pB, gB, SB)
    print("y: {}\n\nz: {}\n\n".format(*to_hex(*assinaturaHashB)))

    # 10.d
    title = ' Item 10.4 - Verificação da assinatura de Beto sobre arq2 '
    print('\n' + title.center(100, '-') + '\n')
    
    verify = elgamal_verify(assinaturaHashB, hash2, pB, gB, TB)
    print(
        "assinatura válida?: {}\n\n"        \
        "lado esquerdo: {}\n\n"  \
        "lado direito: {}\n\n"
    .format(verify[0], *to_hex(*verify[1:])))
    
    # 11
    title = ' Item 11 - Aplicação do algoritmo KEM '
    print('\n' + title.center(100, '-') + '\n')

    ra, ua, SA, TA = KEM_calculate_u(pA, gA)
    rb, ub, SB, TB = KEM_calculate_u(pA, gA)
    print("ua: {}\n\nub: {}\n\n".format(*to_hex(ua, ub)))
    
    ka = KEM_get_key(ra, ub, pA, SA, TB)
    kb = KEM_get_key(rb, ua, pA, SB, TA)
    print("KA: {}\n\nKB: {}\n\n".format(*to_hex(ka, kb)))

    title = ' Item 12 - Distância de Hamming entre KA e KB '
    print('\n' + title.center(100, '-') + '\n')
    print(str(hamming_int(ka, kb)) + '\n')

if __name__ == '__main__':
    main()

