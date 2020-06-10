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


def MV_keygen():

    # Calcula os valores:
    #   public_key = (Q, P) \in E^2
    #   secret_key = s tal que Q = sP
    secret_key = None
    public_key = None

    return secret_key, public_key


# Função de encriptação simples (DE UM BLOCO)
def MV_encrypt(X, public_key):

    # Calcula o valor de Y = (y0, y1, y2) como descrito no enunciado
    k = 84
    
    c1, c2, _ = k * public_key[1]
    
    y0 = k * public_key[0]
    y1 = (c1 * X[0]) % PRIME
    y2 = (c2 * X[1]) % PRIME
    

    # return Y
    return y0, y1, y2


# Função de encriptação usando modo CBC
# (quebra uma mensagem grande em blocos e encripta sequencialmente sob o regime
# CBC - cipher block chaining)
def CBC_MV_encrypt(big_message, public_key):

    # Boa sorte

    # return (Y1, Y2, Y3, ...)
    return None


def MV_decrypt(Y, s, public_key):
    # Calcula o valor de X = (x1, x2) como descrito no enunciado
    c1, c2, _ = s * Y[0]
    
    x1 = Y[1] * c1**(-1)
    x2 = Y[2] * c2**(-1)
    
    # return X
    return x1, x2


# Função de decriptação usando modo CBC
# (quebra uma mensagem grande em blocos e decripta sequencialmente na ordem
# certa sob o regime CBC - cipher block chaining)
def CBC_MV_decrypt(big_ciphertext, public_key):

    # Boa sorte_2

    # return big_message
    return None


def get_binary_representation_512_bits_of_hex(h):
    '''
    Recebe uma string h representando um hexadecimal.
    Devolve a representação binária de h com EXATAMENTE 512 bits
    '''

    bin_h = bin(int(h, 16))[2:]  # [2:] Tira o 0b da frente
    bin_h_512bits = '0' * (512 - len(bin_h)) + bin_h

    return bin_h_512bits


def hamming_distance_with_hex_strings(h1, h2):
    """
    Calcula a distância de hamming entre dois hashes em STRINGS representando
    hexadecimais
    """

    bin_h1 = get_binary_representation_512_bits_of_hex(h1)
    bin_h2 = get_binary_representation_512_bits_of_hex(h2)

    distance = 0
    for x1, x2 in zip(bin_h1, bin_h2):
        if x1 != x2:
            distance += 1
    return distance


def check_if_point_in_curve(point, curve):
    lhs = (point[1] ** 2) % PRIME
    rhs = (point[0] ** 3 + 2 * point[0] + 3) % PRIME
    text = 'pertence' if lhs == rhs else 'não pertence'
    print(f'\nO ponto {point} {text} à curva.\n')

def add_points(p, q):
    delta = (GFp(q[1] - p[1])) / (q[0] - p[0])
    xr = delta ** 2 - p[0] - q[0]
    yr = delta * (p[0] - xr) - p[1]
    return xr, yr



def main():
    """
    Função principal que ordena as chamadas de funções para realizar o que foi
    pedido no EP.
    """
    
    # 1.
    curve = EllipticCurve(GF(263), [0, 0, 0, 2, 3])

    # -----------------------------------------------------------

    # 2.
    P = (200, 39)
    check_if_point_in_curve(P, curve)

    # -----------------------------------------------------------

    # 3.
    num_points = curve.cardinality()
    print(f'\nA curva tem {num_points} pontos.\n')


    # -----------------------------------------------------------

    # 4.
    print('\nPrimeiros 10 pontos da curva:')
    
    P = curve(P)
    for i in range(1, 11):
        print(f'{i}*P = {i*P}')
    
    print('')

    # -----------------------------------------------------------

    # 5.
    R = (175, 80)
    check_if_point_in_curve(R, curve)

    # -----------------------------------------------------------

    # 6.
    P = (200, 39)
    R = (175, 80)

    print(f'\nP + R = {add_points(P, R)}\n')


    # -----------------------------------------------------------
    
    # 7.
    nusp = 4367487
    s = nusp % PRIME

    print(f'\nNUSP % 263 = {s}\n')
    

    # -----------------------------------------------------------

    # 8.
    P = curve((200, 39))
    Q = s * P

    print(f'\nQ = {s} * {P} = {Q}\n')

    # -----------------------------------------------------------

    # 9.
    public_key = (P, Q)
    Y = MV_encrypt(R, public_key)

    print('\n' \
        f'y0 = {Y[0]}\n' \
        f'y1 = {Y[1]}\n' \
        f'y2 = {Y[2]}\n' )

    X = MV_decrypt(Y, s, public_key)
    print(f'\nX = {X}\n')

    # -----------------------------------------------------------
    
    print('----------------------------------------------------\n')

    num_bytes = int(1e5)
    random_bytes = bytearray(os.urandom(num_bytes))
    
    print(1^1)
    print(random_bytes[2]^random_bytes[1])

    return

    documento1 = str(nusp) + random_bytes_hex
    documento1 = bytearray()
    print(f'documento1[:100] = {documento1[:100]}\n\n')

    return

    # -----------------------------------------------------------





    # -----------------------------------------------------------

   

    # -----------------------------------------------------------
    



    # -----------------------------------------------------------



    # -----------------------------------------------------------


if __name__ == '__main__':
    main()
