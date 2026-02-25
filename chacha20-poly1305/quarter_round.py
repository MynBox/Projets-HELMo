from typing import Tuple, List


def sum_mod_232(a: int, b: int) -> int:
    """
    Effectue la somme de deux entiers dans un espace modulo 2 puissance 32.
    :param a: le premier entier.
    :param b: le second entier.
    :return: la somme modulo 2 puissance 32.
    """

    return (a + b) & 0xFFFFFFFF


def circular_shift_left(data: int, input_size: int, n_bit: int) -> int:
    """
    Effectue un décalage circulaire vers la gauche de n_bit bits sur un entier donné de taille connue.

    Un décalage circulaire diffère d’un simple décalage : les bits sortants à gauche sont réinsérés
    à droite (dans l'ordre).

    :param data: l'entier sur lequel est effectué le décalage.
    :param input_size: la taille en bits de l'entier fourni.
    :param n_bit: le nombre de positions de décalage vers la gauche.
    :return: l'entier résultant du décalage circulaire gauche.
    """

    mask = (1 << input_size) - 1

    data &= mask

    return ((data << n_bit) | (data >> (input_size - n_bit))) & mask


def quarter_round(a: int, b: int, c: int, d: int) -> Tuple[int, int, int, int]:
    """
    Implémente l'opération 'Quarter Round' du chiffrement ChaCha20.

    Le quarter round mélange quatre entiers de 32 bits à l'aide d'opérations
    arithmétiques et logiques (addition mod 2^32, XOR, décalages circulaires).
    Cette transformation est conçue pour assurer une forte diffusion des bits.
    NB : Les valeurs de a, b, c et d doivent être des entiers non signés de 32 bits.

    :param a: le premier mot de 32 bits.
    :param b: le deuxième mot de 32 bits.
    :param c: le troisième mot de 32 bits.
    :param d: le quatrième mot de 32 bits.
    :return: les quatre mots modifiés par l'application du 'Quarter Round'.

    """

    a = sum_mod_232(a, b)
    d = d ^ a
    d = circular_shift_left(d, 32, 16)


    c = sum_mod_232(c, d)
    b = b ^ c
    b = circular_shift_left(b, 32, 12)


    a = sum_mod_232(a, b)
    d = d ^ a
    d = circular_shift_left(d, 32, 8)


    c = sum_mod_232(c, d)
    b = b ^ c
    b = circular_shift_left(b, 32, 7)

    return a, b, c, d




def quarter_round_on_selected(state: List[int], indices: List[int]) -> List[int]:
    """
    Applique un 'Quarter Round' de ChaCha20 à quatre mots spécifiques d'un état de ChaCha20.

    Un état de ChaCha20 ne comporte pas quatre nombres entiers, mais seize.
    Cette fonction applique l'opération 'Quarter Round' à quatre nombres prédéterminés.
    NB : seuls les nombres aux positions indiquées sont modifiés.

    :param state: un état de ChaCha20, sous la forme d'un vecteur de 16 entiers de 32 bits.
    :param indices: le vecteur indiquant les 4 indices de 'state' sur lesquels on souhaite appliquer le 'Quarter Round'.
    :return: l'état de ChaCha20  modifié par l'application du 'Quarter Round'.

    """

    idx_a, idx_b, idx_c, idx_d = indices

    a = state[idx_a]
    b = state[idx_b]
    c = state[idx_c]
    d = state[idx_d]


    a, b, c, d = quarter_round(a, b, c, d)


    state[idx_a] = a
    state[idx_b] = b
    state[idx_c] = c
    state[idx_d] = d

    return state
