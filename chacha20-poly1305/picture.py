import os
import secrets

import numpy as np
from PIL import Image
from numpy import asarray

from aead_chacha20_poly1305 import aead_chacha20_poly1305_encrypt, aead_chacha20_poly1305_decrypt



def image_from_file_to_bytes(path):
    image = Image.open(path)
    # summarize some details about the image
    # print(image.format)
    # print(image.size)
    # print(image.mode)
    # asarray() class is used to convert PIL images into NumPy arrays
    numpy_data = asarray(image)
    # <class 'numpy.ndarray'>
    # print(type(numpydata))
    #  shape
    buffer = numpy_data.data
    # (x, y, z) = buffer.shape
    # if (x * y * z * 8) % 128 != 0:
    #    print("Your picture must have size as multiple of 128")
    #    exit(-1)
    # print(buffer.tobytes())
    return buffer.tobytes(), buffer.shape


def image_from_bytes_to_file(img_bytes, img_shape, path):
    numpy_cipher_data = np.reshape(np.frombuffer(img_bytes, dtype=np.uint8), newshape=img_shape)
    Image.fromarray(numpy_cipher_data).save(path)


def bytes_to_block128(data_bytes):
    blocks = []
    i = 15
    block = 0
    for pixel in data_bytes:
        # print(i, "{:08b}".format(pixel))
        block |= pixel << 8 * i
        i -= 1
        if i < 0:
            blocks.append(block)
            i = 15
            block = 0
    return blocks


def block128_to_bytes(blocks):
    data_bytes = bytes()
    for block in blocks:
        data_bytes += block.to_bytes(16)
    return data_bytes


def demander_aad():
    """
    Demande à l'utilisateur de fournir les données additionnelles authentifiées (AAD).
    Capture et renvoie les AAD sous forme d'octets (bytes).
    """
    aad = None
    while not aad:
        aad = input("AAD (données additionnelles authentifiées non chiffrées) : ").strip()
    return aad


def encrypt_bytes(data_bytes: bytes) -> bytes:
    """
    Appel de la fonction  aead_chacha20_poly1305_encrypt()
        qui nécessite 4 paramètres :
            - key: la clé de chiffrement (256 bits)  -> générée aléatoirement ;
            - nonce: le nonce (96 bits) (doit être unique pour chaque opération de chiffrement avec la même clé)
                    -> générée aléatoirement ;
            - plaintext: le texte clair à chiffrer, de longueur arbitraire ;  -> data_bytes
            - aad: les données additionnelles authentifiées (mais pas chiffrées)
                    -> demandées à l'utilisateur ;
        et qui renvoie :
            - le texte chiffré (même longueur que `plaintext`) et
            - le tag d'authentification Poly1305 (16 octets).

    :param data_bytes: les données à chiffrer.
    :return: les données chiffrées.

    IMPORTANT : les informations nécessaires pour le déchiffrement sont affichées en console.
    """
    # Génération d'une clé aléatoire de 256 bits
    key = secrets.token_bytes(32)
    # Génération d'un nonce de 96 bits
    nonce = secrets.token_bytes(12)
    # Génération des données additionnelles
    aad = demander_aad()

    # Appel à la fonction encrypt Chacha20-poly1305
    cipher_bytes, tag = aead_chacha20_poly1305_encrypt(int.from_bytes(key), int.from_bytes(nonce),
                                                       data_bytes, aad.encode("utf-8"))

    # Affichage des paramètres de chiffrement
    print(f"\nIMPORTANT - Conservez ces informations : elles sont indispensables pour déchiffrer l'image :")
    print(f"Clé générée : {key.hex()}")
    print(f"Nonce: {nonce.hex()}")
    print(f"Aad: {aad}")
    print(f"Tag: {tag.hex()}")

    return cipher_bytes


def demander_cle():
    """
    Demande à l'utilisateur d'encoder la clé de chiffrement en hexadécimal.
    Capture et renvoie la clé sous forme d'un entier de 256 bits.
    """
    cle_hex = input("Veuillez entrer la clé utilisée pour le chiffrement (hexadecimal) : ")
    cle_int = int(cle_hex, 16)
    try:
        if cle_int < 0:
            raise ValueError("La clé ne peut pas être négative.")
        if cle_int >= 2 ** 256:
            raise ValueError("La clé dépasse 256 bits. La valeur maximale est 2^256 - 1.")
        return cle_int

    except ValueError as e:
        print(f"Erreur : {e}")
        return demander_cle()


def demander_nonce():
    """
    Demande à l'utilisateur d'encoder le nonce généré lors du chiffrement en hexadécimal.
    Capture et renvoie le nonce sous forme d'octets (bytes).
    """
    nonce_hex = input("Veuillez entrer le nonce utilisé pour le chiffrement (hexadecimal) : ").strip()

    # Vérification que le nonce est valide (longueur 96 bits en hexadécimal)
    try:
        # Vérifier si la longueur correspond à 96 bits (24 caractères hexadécimaux)
        if len(nonce_hex) != 24:
            raise ValueError("Le nonce doit être de 96 bits (24 caractères hexadécimaux).")

        # Convertir le tag hexadécimal en bytes
        nonce_bytes = bytes.fromhex(nonce_hex)
        return nonce_bytes

    except ValueError as e:
        print(f"Erreur : {e}")
        return demander_nonce()  # Redemander le nonce si il est invalide


def demander_tag():
    """
    Demande à l'utilisateur d'encoder le tag généré lors du chiffrement en hexadécimal.
    Capture et renvoie le tag sous forme d'octets (bytes).
    """
    tag_hex = input("Veuillez entrer le tag utilisé pour le chiffrement (hexadecimal) : ").strip()

    # Vérification que le tag est valide (longueur 128 bits en hexadécimal)
    try:
        # Vérifier si la longueur correspond à 128 bits (32 caractères hexadécimaux)
        if len(tag_hex) != 32:
            raise ValueError("Le tag doit être de 128 bits (32 caractères hexadécimaux).")

        # Convertir le tag hexadécimal en bytes
        tag_bytes = bytes.fromhex(tag_hex)
        return tag_bytes

    except ValueError as e:
        print(f"Erreur : {e}")
        return demander_tag()  # Redemander le tag si il est invalide



def decrypt_bytes(cipher_bytes: bytes) -> bytes:
    """
    Appel de la fonction  aead_chacha20_poly1305_decrypt()
        qui nécessite 4 paramètres :
            - key: la clé de déchiffrement (256 bits); elle doit être identique à la clé utilisée lors du chiffrement
                    -> demandée à l'utilisateur ;
            - nonce: le nonce (96 bits); il doit être identique au nonce utilisé lors du chiffrement
                    -> demandé à l'utilisateur ;
            - ciphertext: les données chiffrées à déchiffrer ;
            - aad: les données additionnelles authentifiées; elles doivent être identiques aux données AAD utilisées
                    lors du chiffrement pour que l'authentification réussisse
                    -> demandées à l'utilisateur.
        et qui renvoie :
            - les données déchiffrées (même longueur que `plaintext`) et
            - le tag d'authentification recalculé (16 octets).

    :param cipher_bytes: les données à chiffrer.
    :return: les données déchiffrées.

    Note : La vérification du tag doit être faite par l'appelant (comparaison constante).

    """
    # Demander clé utilisée pour le chiffrement
    key = demander_cle()
    # Demander nonce utilisé pour le chiffrement
    nonce = demander_nonce()
    # Demander tag généré lors du chiffrement
    receive_tag = demander_tag()
    # Demander aad utilisées lors du chiffrement
    aad = demander_aad()


    # Appel à la fonction decrypt Chacha20-poly1305
    data_bytes, tag = aead_chacha20_poly1305_decrypt(key, int.from_bytes(nonce),
                                                     cipher_bytes, aad.encode("utf-8"))
    print("receive tag: ", receive_tag.hex())
    print("check tag: ", tag.hex())
    if tag != receive_tag:
       raise ValueError("Le tag ne correspond pas. Soit les données sont corrompues, soit vos données additionnelles "
                        "d'authentification sont erronées.")
    else:
        print("Le contrôle du TAG a réussi.")
    return data_bytes


def encrypt_image(path: str):
    image_bytes, img_shape = image_from_file_to_bytes(path)
    # print(img_shape)
    cipher_bytes = encrypt_bytes(image_bytes)

    filename = os.path.basename(path)
    directory = os.path.dirname(path) + '\\..\\Encrypted'

    image_from_bytes_to_file(cipher_bytes, img_shape, os.path.join(directory, filename))


def decrypt_image(path: str):
    filename = os.path.basename(path)
    directory = os.path.dirname(path) + '\\..\\Decrypted'

    cipher_bytes, img_shape = image_from_file_to_bytes(path)

    image_bytes = decrypt_bytes(cipher_bytes)

    image_from_bytes_to_file(image_bytes, img_shape, os.path.join(directory, filename))
