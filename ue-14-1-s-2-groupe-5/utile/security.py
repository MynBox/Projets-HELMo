from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json





def aes_encrypt(msg, key):
    """
    Fonction de chiffrement AES-GCM
    :param msg: (dict) Message au format de dictionnaire à chiffrer
    :param key: (bytes) Clé de chiffrement
    :return: (list) Liste des éléments nécessaires au déchiffrement --> [nonce, header, ciphertext, tag]
    """
    header = "Zidane...Parce qu'il est chauve et chauve...tête quoi".encode("utf-8")
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(msg).encode("utf-8"))

    json_v = [b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag)]

    return json_v
    #But de la fonction : Elle chiffre le message et retourne des éléments pour pouvoir le déchiffrer plus tard.

def aes_decrypt(msg, key):
    """
    Fonction de déchiffrement AES-GCM
    :param msg: (list) Liste des éléments nécessaires au déchiffrement --> [nonce, header, ciphertext, tag]
    :param key: (bytes) Clé de chiffrement
    :return: (dict) Message déchiffré sous forme de dictionnaire
    """

    try:
        # Décodage des valeurs en Base64, parce que AES fonctionne avec le binaire
        nonce, header, ciphertext, tag = [b64decode(x) for x in msg]

        # Création du cipher AES-GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(header)

        # Déchiffrement et vérification de l'intégrité
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        return json.loads(plaintext.decode("utf-8"))  # Retourne un dictionnaire

    except (ValueError, KeyError):
        print("Erreur : déchiffrement incorrect")
        return None  # En cas d'échec, retourne None


def gen_key(size=256):
    """
    Fonction générant une clé de chiffrement
    :param size: (bits) taille de la clé à générer
    :return: (bytes) nouvelle clé de chiffrement
    """
    size //= 8
    key = get_random_bytes(size)

    return key
