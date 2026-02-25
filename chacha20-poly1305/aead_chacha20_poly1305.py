from typing import Tuple
from chacha20 import chacha20_encrypt
from poly1305 import poly1305_key_gen_chacha20, poly1305_mac

def pad16(data: bytes) -> bytes:
    """
    Fonction utilitaire pour générer le padding de zéros nécessaire
    pour aligner les données sur 16 octets.
    """
    length = len(data)
    if length % 16 == 0:
        return b""
    return b'\x00' * (16 - (length % 16))


def num_to_8_le_bytes(n: int) -> bytes:
    """
    Convertit un nombre en 8 octets (64 bits) little-endian.
    Utilisé pour les champs de longueur dans le calcul du MAC.
    """
    return n.to_bytes(8, 'little')

def aead_chacha20_poly1305_encrypt(key: int, nonce: int, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    """
    Implémente le chiffrement authentifié avec données associées (AEAD) selon l'algorithme ChaCha20-Poly1305
    conformément à la RFC 8439.
    Cette fonction combine le chiffrement par flux ChaCha20 avec l'authentification par MAC Poly1305
    pour assurer à la fois la confidentialité et l'intégrité des données.

    :param key: la clé de chiffrement (256 bits); cette clé est utilisée à la fois pour générer la clé Poly1305 et
                pour le chiffrement ChaCha20.
    :param nonce: le nonce (96 bits) (doit être unique pour chaque opération de chiffrement avec la même clé).
    :param plaintext: le texte clair à chiffrer, de longueur arbitraire.
    :param aad: les données additionnelles authentifiées (mais pas chiffrées).
    :return: le texte chiffré (même longueur que `plaintext`) et le tag d'authentification Poly1305 (16 octets).
    """

    otk = poly1305_key_gen_chacha20(key, nonce)

    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)

    mac_data = bytearray()
    mac_data.extend(aad)
    mac_data.extend(pad16(aad))
    mac_data.extend(ciphertext)
    mac_data.extend(pad16(ciphertext))
    mac_data.extend(num_to_8_le_bytes(len(aad)))
    mac_data.extend(num_to_8_le_bytes(len(ciphertext)))

    tag = poly1305_mac(bytes(mac_data), otk)

    return ciphertext, tag


def aead_chacha20_poly1305_decrypt(key: int, nonce: int, ciphertext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    """
    Implémente le déchiffrement authentifié avec données associées (AEAD) selon l'algorithme ChaCha20-Poly1305
    conformément à la RFC 8439.
    Cette fonction déchiffre les données chiffrées par `aead_chacha20_poly1305_encrypt()`et
    recalcule le tag d'authentification pour vérification.

    :param key: la clé de déchiffrement (256 bits); elle doit être identique à la clé utilisée lors du chiffrement.
    :param nonce: le nonce (96 bits); il doit être identique au nonce utilisé lors du chiffrement.
    :param ciphertext: les données chiffrées à déchiffrer, de longueur arbitraire.
    :param aad: les données additionnelles authentifiées; elles doivent être identiques aux données AAD utilisées
                lors du chiffrement pour que l'authentification réussisse.
    :return: le texte déchiffré (même longueur que `ciphertext`) et le tag d'authentification recalculé (16 octets).

    Note : La vérification du tag doit être faite par l'appelant (comparaison constante).
    """

    otk = poly1305_key_gen_chacha20(key, nonce)

    plaintext = chacha20_encrypt(key, 1, nonce, ciphertext)

    mac_data = bytearray()
    mac_data.extend(aad)
    mac_data.extend(pad16(aad))
    mac_data.extend(ciphertext)
    mac_data.extend(pad16(ciphertext))
    mac_data.extend(num_to_8_le_bytes(len(aad)))
    mac_data.extend(num_to_8_le_bytes(len(ciphertext)))

    tag = poly1305_mac(bytes(mac_data), otk)

    return plaintext, tag