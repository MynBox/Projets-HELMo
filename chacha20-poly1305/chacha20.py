from typing import List

from block_function import state_builder, block_function, serialize


def chacha20_encrypt(key: int, counter: int, nonce: int, plaintext: bytes) -> bytes:
    """
    Chiffre un message avec l’algorithme ChaCha20.

    ChaCha20 génère un flot de clés de 64 octets (512 bits) par appel à la fonction de bloc,
    puis applique un XOR entre ce flot et le texte clair.

    :param key: la clé (256 bits).
    :param counter: le compteur de blocs initial (32 bits).
        Note : Cette valeur peut être définie comme étant n'importe quel nombre, mais sera généralement zéro ou un.
               Il est logique d'utiliser un si le bloc zéro est utilisé pour autre chose, comme générer une clé
               d'authentification à usage unique (dans le cadre d'un )algorithme AEAD).
    :param nonce: le nonce (96 bits).
    :param plaintext: le texte clair à chiffrer.
    :return: le texte chiffré (même longueur que `plaintext`).
    """
    encrypted_message = bytearray()

    num_blocks = (len(plaintext) + 63) // 64

    for i in range(num_blocks):

        current_counter = (counter + i) & 0xFFFFFFFF
        state = state_builder(key, current_counter, nonce)

        block_output = block_function(state)

        keystream_int = serialize(block_output)

        keystream_bytes = keystream_int.to_bytes(64, 'big')

        start = i * 64
        end = min((i + 1) * 64, len(plaintext))
        chunk = plaintext[start:end]

        current_keystream = keystream_bytes[:len(chunk)]
        encrypted_chunk = bytes(a ^ b for a, b in zip(chunk, current_keystream))

        encrypted_message.extend(encrypted_chunk)

    return bytes(encrypted_message)
