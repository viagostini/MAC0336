# coding: utf-8

"""
    Esqueleto para o EP2 de Cripto 2020
    Prof. Routo Terada
    Monitor: Thales Paiva

    Para rodar:
    [~/cripto-2020/ep1]$ sage ep1_esqueleto.py
"""

from sage.all import *
from collections import namedtuple


import sys


# Parâmetro público p: a característica do corpo finito usado para instanciar
# a curva elíptica
PRIME = 263
GFp = GF(263)
curve = EllipticCurve(GFp, [0, 0, 0, 2, 3])


# Função de encriptação simples (DE UM BLOCO)
def MV_encrypt(X, public_key):
    c1 = c2 = 0
    while not c1 or not c2: 
        k = randint(1, PRIME-1)
        c1, c2, _ = k * public_key[1]
    
    P = curve(public_key[0])
    y0 = k * P
    y1 = (c1 * X[0]) % PRIME
    y2 = (c2 * X[1]) % PRIME

    return [list(y0.xy()), y1, y2]


# Função de encriptação usando modo CBC
# (quebra uma mensagem grande em blocos e encripta sequencialmente sob o regime
# CBC - cipher block chaining)
#
# init_vector deve ser um inteiro representando o vetor de inicialização
# por exemplo: 0 = 00..00, 5 = 00..0101
def CBC_MV_encrypt(big_message, public_key, init_vector):
    xor_1 = xor_2 = init_vector
    
    all_y = []
    for first, second in iter_pairs(big_message):
        X = (first % 256) ^ xor_1, (second % 256) ^ xor_2
        y0, y1, y2 = MV_encrypt(X, public_key)
        
        xor_1 = int(y1) % 256
        xor_2 = int(y2) % 256
        
        y0 = [convert_to_bytes(x, 2) for x in y0]
        y1 = convert_to_bytes(y1, 2)
        y2 = convert_to_bytes(y2, 2)

        all_y.append([y0, y1, y2])

    return all_y


def MV_decrypt(Y, secret_key, public_key):
    Y[0] = curve(Y[0])
    c1, c2, _ = secret_key * Y[0]
    
    x1 = Y[1] * c1**(-1)
    x2 = Y[2] * c2**(-1)

    return [x1, x2]

# Função de decriptação usando modo CBC
# (quebra uma mensagem grande em blocos e decripta sequencialmente na ordem
# certa sob o regime CBC - cipher block chaining)
def CBC_MV_decrypt(big_ciphertext, s, public_key, init_vector):
    for block in big_ciphertext:
        block[1:] = map(convert_from_bytes, block[1:])
    
    xor_1 = xor_2 = init_vector
    dec = []
    for block in big_ciphertext:
        block[0] = list(map(convert_from_bytes, block[0]))
        x = MV_decrypt(block, s, public_key)
        x[0] = (int(x[0]) % 256) ^ xor_1
        x[1] = (int(x[1]) % 256) ^ xor_2

        xor_1 = int(block[1]) % 256
        xor_2 = int(block[2]) % 256

        dec.append(x)

    for block in dec:
        block[0] = convert_to_bytes(block[0], 1)
        block[1] = convert_to_bytes(block[1], 1)

    return dec


def get_binary_representation_4M_bits_of_hex(h):
    '''
    Recebe uma string h representando um hexadecimal.
    Devolve a representação binária de h com EXATAMENTE 4M bits
    (Assume que sua representação cabe em 4M bits).
    '''

    bin_h = bin(int(h, 16))[2:]  # [2:] Tira o 0b da frente
    bin_h_4Mbits = '0' * (4000000 - len(bin_h)) + bin_h

    return bin_h_4Mbits


def hamming_distance_with_hex_strings(h1, h2):
    """
    Calcula a distância de hamming entre dois hashes em STRINGS representando
    hexadecimais
    """

    bin_h1 = get_binary_representation_4M_bits_of_hex(h1)
    bin_h2 = get_binary_representation_4M_bits_of_hex(h2)

    distance = 0
    for x1, x2 in zip(bin_h1, bin_h2):
        if x1 != x2:
            distance += 1
    return distance


def check_if_point_in_curve(point, curve):
    lhs = (point[1] ** 2) % PRIME
    rhs = (point[0] ** 3 + 2 * point[0] + 3) % PRIME
    text = 'pertence' if lhs == rhs else 'não pertence'
    print(f'O ponto {point} {text} à curva.\n')

def add_points(p, q):
    delta = (GFp(q[1] - p[1])) / (q[0] - p[0])
    xr = delta ** 2 - p[0] - q[0]
    yr = delta * (p[0] - xr) - p[1]
    return xr, yr

def iter_pairs(iterable):
    '''
    Função para iterar pelos blocos em pares (1 byte, 1 byte)
    '''
    iter1 = iter(iterable)
    while True:
        try:
            first = next(iter1)
            second = next(iter1)
            yield first, second
        except StopIteration:
            break

def convert_from_bytes(x):
    return int.from_bytes(x, 'little')

def convert_to_bytes(x, num_bytes):
    return (int(x)).to_bytes(num_bytes, 'little')

def main():
    """
    Função principal que ordena as chamadas de funções para realizar o que foi
    pedido no EP.
    """
    
    # 1.
    # a curva está global

    # -----------------------------------------------------------

    # 2.
    print('2.')
    P = (200, 39)
    check_if_point_in_curve(P, curve)

    # -----------------------------------------------------------

    # 3.
    print('3.')
    num_points = curve.cardinality()
    print(f'A curva tem {num_points} pontos.\n')


    # -----------------------------------------------------------

    # 4.
    print('4.')
    print('Primeiros 10 pontos da curva:')
    
    P = curve(P)
    for i in range(1, 11):
        print(f'{i}*P = {i*P}')
    
    print('')

    # -----------------------------------------------------------

    # 5.
    print('5.')
    R = (175, 80)
    check_if_point_in_curve(R, curve)

    # -----------------------------------------------------------

    # 6.
    P = (200, 39)
    R = (175, 80)

    print('6.')
    print(f'P + R = {add_points(P, R)}\n')


    # -----------------------------------------------------------
    
    # 7.
    nusp = 4367487
    s = nusp % PRIME

    print('7.')
    print(f'NUSP % 263 = {s}\n')
    

    # -----------------------------------------------------------

    # 8.
    P = curve((200, 39))
    Q = s * P

    print('8.')
    print(f'Q = {s} * {P} = {Q}\n')

    # -----------------------------------------------------------

    # 9.
    P = (200, 39)
    R = (175, 80)
    public_key = (P, Q)
    Y = MV_encrypt(R, public_key)

    print('9.')
    print(f'y0 = {Y[0]}\n' \
          f'y1 = {Y[1]}\n' \
          f'y2 = {Y[2]}\n' )

    # -----------------------------------------------------------

    # 10.
    print('10.')

    X = MV_decrypt(Y, s, public_key)
    print(f'X = {X}\n')

    # -----------------------------------------------------------
    
    print('----------------------------------------------------\n')

    # 11.
    num_bytes = 16*7000 - len(str(nusp))
    nusp_bytes = b'4367487'
    random_bytes = os.urandom(num_bytes)

    documento1 = nusp_bytes + random_bytes
    print('11.')
    print(f'documento1[:100] = {documento1[:100]}\n\n')

    # -----------------------------------------------------------
    
    # 12.
    init_vector = 0
    Y = CBC_MV_encrypt(documento1, public_key, init_vector)

    concat = lambda s: b''.join([concat(x) if type(x) is list else x for x in s])
    
    doc1_cript = concat(Y)

    print('12.')
    print(f'doc1-cript[:100] = {doc1_cript[:100]}\n')
    
    # -----------------------------------------------------------
    
    # 13.
    init_vector = 0
    X = CBC_MV_decrypt(Y, s, public_key, init_vector)

    doc1_cript_inv = b''
    for block in X:
        doc1_cript_inv = b''.join([doc1_cript_inv, *block])

    print('13.')
    print(f'doc1-cript-inverso[:100] = {doc1_cript_inv[:100]}\n')


    # -----------------------------------------------------------
    
    # 15.
    num_bytes = 16*7000 - len(str(nusp))
    nusp_bytes = b'5367487'
    random_bytes = os.urandom(num_bytes)

    documento2 = nusp_bytes + random_bytes
    print('15.')
    print(f'documento2[:100] = {documento2[:100]}\n\n')

    # -----------------------------------------------------------

    # 16.
    init_vector = 0
    Y = CBC_MV_encrypt(documento2, public_key, init_vector)

    concat = lambda s: b''.join([concat(x) if type(x) is list else x for x in s])
    
    doc2_cript = concat(Y)

    print('16.')
    print(f'doc2-cript[:100] = {doc2_cript[:100]}\n')

    # -----------------------------------------------------------
    
    # 17. Resposta: É desejável que a distância seja alta (alta entropia)
    #               para que seja mais difícil obter informações

    print('17.')
    h = hamming_distance_with_hex_strings(doc1_cript.hex(), doc2_cript.hex())
    print(f'Distância entre doc1-cript e doc2-cript = {h}\n')


    # -----------------------------------------------------------

    # 18.
    print('18.')

    s_beto = randint(1, PRIME-1)
    
    P = curve((200, 39))
    Q_beto = s_beto * P

    print(f'Q_beto = {s} * {P} = {Q}\n')

    # -----------------------------------------------------------

    # 19.
    init_vector = 0
    P = (200, 39)
    public_key = (P, Q_beto)
    Y = CBC_MV_encrypt(documento1, public_key, init_vector)

    concat = lambda s: b''.join([concat(x) if type(x) is list else x for x in s])
    
    doc1_cript_beto = concat(Y)

    print('19.')
    print(f'doc1-cript-Beto[:100] = {doc1_cript_beto[:100]}\n')

    # -----------------------------------------------------------

    # 20.
    print('20.')
    h = hamming_distance_with_hex_strings(doc1_cript.hex(), doc1_cript_beto.hex())
    print(f'Distância entre doc1-cript e doc1-cript-Beto = {h}\n')




if __name__ == '__main__':
    main()
