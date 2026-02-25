from typing import List
from quarter_round import quarter_round_on_selected, sum_mod_232

CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

def reverse_blocks_of_4(data: int) -> int:
    """
    Inverse l'ordre des octets à l'intérieur de chaque mot (bloc de 4 octets) : le bloc 1 devient le bloc 4,
    le bloc 2 devient le bloc 3, le bloc 3 devient le bloc 2 et le bloc 4 devient le bloc 1.

    :param data: un entier (mot de 32 bits = 4 octets).
    :return: cet entier après inversion des octets.
    """

    b0 = (data & 0x000000FF)
    b1 = (data & 0x0000FF00) >> 8
    b2 = (data & 0x00FF0000) >> 16
    b3 = (data & 0xFF000000) >> 24

    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3


def int_to_words(int_value: int, length: int) -> List[int]:
    """
    Convertit un entier de longueur donnée en une liste de mots de 32 bits.

    Cette fonction est utilisée pour transformer une clé (256 bits) ou un nonce (96 bits)
    en une liste de mots de 32 bits, dans l’ordre attendu par ChaCha20.

    :param int_value: un entier (max 256 bits).
    :param length: la taille en bits de l'entier (doit être multiple de 32).
    :return: une liste de mots 32 bits (endianness ChaCha20).
    """
    num_words = length // 32
    words = []

    for i in range(num_words):

        chunk = (int_value >> (i * 32)) & 0xFFFFFFFF

        words.append(reverse_blocks_of_4(chunk))
    words.reverse()
    return words


def state_builder(key: int, counter: int, nonce: int) -> List[int]:
    """
    Construit un état de ChaCha20 (16 mots de 32 bits).

    Un état ChaCha20 est constitué comme suit :
    - les 4 premiers mots (positions 0-3) sont des constantes : 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 ;
    - les 8 mots suivants (positions 4-11) sont extraits de la clé 256 bits, par blocs de 4 octets (lecture dans l'ordre little-endian) ;
    - le mot suivant (position 12) est un compteur de blocs (32 bits) ;
    - les 3 derniers mots (positions 13-15) sont issus du nonce 96 bits (lecture dans l'ordre little-endian).

    :param key: la clé (256 bits).
    :param counter: le compteur de blocs (32 bits).
    :param nonce: le nonce (96 bits).
    :return: un état initial de ChaCha20, sous la forme d'une liste de 16 entiers 32 bits.
    """
    state = [0] * 16

    state[0] = CONSTANTS[0]
    state[1] = CONSTANTS[1]
    state[2] = CONSTANTS[2]
    state[3] = CONSTANTS[3]

    key_words = int_to_words(key, 256)
    for i in range(8):
        state[4 + i] = key_words[i]

    state[12] = counter & 0xFFFFFFFF

    nonce_words = int_to_words(nonce, 96)
    for i in range(3):
        state[13 + i] = nonce_words[i]

    return state


def column_rounds(state: List[int]) -> List[int]:
    """
    Applique l'opération 'Quarter Round' aux colonnes d'un état ChaCha20.

    Un état ChaCha20 comporte seize nombres entiers (32 bits) ; il est présenté sous la forme d'une matrice 4x4.
    La fonction column_round() applique successivement l'opération 'Quarter Round' à chaque colonne de l'état ChaCha
    fourni en argument (indices [0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]).

    :param state: un état de ChaCha20, sous la forme d'un vecteur de 16 entiers de 32 bits.
    :return: l'état de ChaCha20 modifié par l'application de column_round().
    """
    quarter_round_on_selected(state, [0, 4, 8, 12])
    quarter_round_on_selected(state, [1, 5, 9, 13])
    quarter_round_on_selected(state, [2, 6, 10, 14])
    quarter_round_on_selected(state, [3, 7, 11, 15])
    return state


def diagonal_rounds(state: List[int]) -> List[int]:
    """
    Applique l'opération 'Quarter Round' aux diagonales d'un état ChaCha20.

    Un état ChaCha20 comporte seize nombres entiers (32 bits) ; il est présenté sous la forme d'une matrice 4x4.
    La fonction diagonal_round() applique successivement l'opération 'Quarter Round' à chaque diagonale de l'état ChaCha
    fourni en argument (indices [0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]).

    :param state: un état de ChaCha20, sous la forme d'un vecteur de 16 entiers de 32 bits.
    :return: l'état de ChaCha20 modifié par l'application de diagonal_round().
    """
    quarter_round_on_selected(state, [0, 5, 10, 15])
    quarter_round_on_selected(state, [1, 6, 11, 12])
    quarter_round_on_selected(state, [2, 7, 8, 13])
    quarter_round_on_selected(state, [3, 4, 9, 14])
    return state


def twenty_rounds(state: List[int]) -> List[int]:
    """
    Applique 20 rounds de ChaCha20 (10 double-rounds) à un état donné.

    NB : un double-round = un appel à column_rounds() suivi d'un appel à diagonal_rounds().

    :param state: un état de ChaCha20, sous la forme d'un vecteur de 16 entiers de 32 bits.
    :return: l'état de ChaCha20 après 20 rounds.
    """
    for _ in range(10):
        column_rounds(state)
        diagonal_rounds(state)
    return state


def add_lists_mod32(state1: List[int], state2: List[int]) -> List[int]:
    """
    Effectue l'addition mot à mot de deux états de ChahCha dans un espace modulo 2 puissance 32.

    Cette fonction est utilisée dans la fonction de bloc pour mélanger l'état initial
    et l'état après 20 rounds.

    :param state1: le premier état (16 entiers 32 bits).
    :param state2: le second état (16 entiers 32 bits).
    :return: la liste résultante (16 entiers 32 bits).
    """
    result = [0] * 16
    for i in range(16):
        result[i] = sum_mod_232(state1[i], state2[i])
    return result


def block_function(state: List[int]) -> List[int]:
    """
    Fonction de bloc de ChaCha20.
    - Elle copie l'état initial de ChaCha20;
    - Elle applique 20 rounds;
    - Elle additionne, mot à mot, l'état initial et l'état transformé (mod 2^32).

    :param state: un état de ChaCha20, sous la forme d'un vecteur de 16 entiers de 32 bits.
    :return: l'état de ChaCha20 modifié par l'application de block_function().
    """

    working_state = list(state)

    twenty_rounds(working_state)

    return add_lists_mod32(state, working_state)


def serialize(state: List[int]) -> int:
    """
    Sérialise un état de ChaCha20 (16 mots de 32 bits) en un entier de 512 bits (64 octets).

    Chaque mot est converti en little-endian, puis concaténé pour former un entier de 512 bits.

    :param state: un état de ChaCha20, sous la forme d'un vecteur de 16 entiers de 32 bits.
    :return: un entier de 512 bits représentant le bloc chiffrant.
    """

    result = 0
    for i in range(16):

        val = reverse_blocks_of_4(state[i])

        shift = (15 - i) * 32
        result |= (val << shift)

    return result


def next_state(state: List[int]) -> List[int]:
    """
    Incrémente le compteur (13ème mot de l'état) pour générer le bloc suivant.

    :param state: un état de ChaCha20, sous la forme d'un vecteur de 16 entiers de 32 bits.
    :return: l'état de ChaCha20  dans lequel le compteur a été incrémenté de 1.
    """

    state[12] = (state[12] + 1) & 0xFFFFFFFF
    return state
