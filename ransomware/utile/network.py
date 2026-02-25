import socket
import time
import json
from hashlib import sha256
from secrets import randbelow
import ssl

from Crypto.Util.number import getPrime
from sympy import isprime, primefactors

from utile.security import aes_encrypt, aes_decrypt

# Constantes
HEADERSIZE = 10
LOCAL_IP = socket.gethostbyname(socket.gethostname())
PORT_SERV_CLES = 8380


def start_net_serv(ip=LOCAL_IP, port=PORT_SERV_CLES):
    """
    Démarre un socket qui écoute en mode "serveur" sur ip:port
    :param ip: l'adresse ip à utiliser
    :param port: le port à utiliser
    :return: le socket créé en mode "serveur"
    """
    serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv_sock.bind((ip, port))
    serv_sock.listen(5)
    # print(f"Serveur démarré sur {ip}:{port}")
    return serv_sock

def connect_to_serv(ip=LOCAL_IP, port=PORT_SERV_CLES, retry=60):
    """
    Crée un socket qui tente de se connecter sur ip:port.
    En cas d'échec, tente une nouvelle connexion après retry secondes
    :param ip: l'adresse ip où se connecter
    :param port: le port de connexion
    :param retry: le nombre de secondes à attendre avant de tenter une nouvelle connexion
    :return: le socket créé en mode "client"
    """
    while True:
        try:
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.connect((ip, port))
            print(f"Connecté à {ip}:{port}")
            return client_sock
        except ConnectionRefusedError:
            print(f"Connexion refusée. Nouvelle tentative dans {retry} secondes...")
            time.sleep(retry)

def send_message(s, msg=b''):
    """
    Envoie un message sur le réseau
    :param s: (socket) pour envoyer le message
    :param msg: (dictionary) message à envoyer
    :return: Néant
    """

    msg_serialized = json.dumps(msg).encode('utf-8')  # Convertir en JSON et encoder en bytes
    msg_length = f"{len(msg_serialized):<{HEADERSIZE}}".encode('utf-8')
    s.send(msg_length + msg_serialized)

def receive_message(s):
    """
    Réceptionne un message sur le réseau
    :param s: (socket) pour réceptionner le message
    :return: (objet) réceptionné
    """
    # Lire le header
    msg_header = s.recv(HEADERSIZE)
    if not msg_header or len(msg_header) < HEADERSIZE:
        return None

    try:
        msg_length = int(msg_header.decode('utf-8').strip())
    except ValueError:
        print("Erreur : en-tête de message corrompu.")
        return None

    # Lire le corps du message en boucle jusqu'à tout recevoir
    msg_data = b''
    while len(msg_data) < msg_length:
        part = s.recv(msg_length - len(msg_data))
        if not part:
            print("Erreur : connexion interrompue avant réception complète.")
            return None
        msg_data += part

    try:
        return json.loads(msg_data.decode('utf-8'))
    except json.JSONDecodeError:
        print("Erreur : données JSON reçues invalides.")
        return None

def find_primitive_root(p):
    """
    Trouve une racine primitive modulo p.
    Ce qui permet de respecter la relation importante entre "g" et "p"
    qui est que "g" doit être une racine primitive modulo "p".
    """
    if not isprime(p):
        return None  # Vérifie que p est bien un nombre premier

    phi = p - 1  # Euler's totient function
    factors = primefactors(phi)  # Facteurs premiers de p-1

    for g in range(2, p):
        if all(pow(g, phi // f, p) != 1 for f in factors):
            return g
    return None

def diffie_hellman_send_key(s_client):
    """
    Fonction d'échange de clé via le protocole de Diffie-Hellman
    :param s_client: (socket) Connexion TCP du client avec qui échanger les clés
    :return: (bytes) Clé de 256 bits calculée
    """
    p = getPrime(64) #2048 temps de calcul trop long
    cle_privee = randbelow(p-3) + 2 # Comme ça, c'est entre 2 et x (-3, car p-3 non inclus)
    g = find_primitive_root(p)
    cle_publique_serveur = pow(g, cle_privee, p) #g**cle_privee % p

    diffie_hellman = (g, p, cle_publique_serveur)

    send_message(s_client, diffie_hellman)

    cle_publique_client = receive_message(s_client)

    cle_partagee = pow(cle_publique_client, cle_privee, p)

    cle_partagee = str(cle_partagee).encode("utf-8")

    return sha256(cle_partagee).digest()


def diffie_hellman_recv_key(s_serveur):
    """
    Fonction d'échange de clé via le protocole de Diffie-Hellman
    :param s_serveur: (socket) Connexion TCP du serveur avec qui échanger les clés
    :return: (bytes) Clé de 256 bits calculée
    """

    g, p, cle_publique_serveur = receive_message(s_serveur)

    cle_privee = randbelow(p - 3) + 2

    cle_publique_client = pow(g,cle_privee, p)

    send_message(s_serveur, cle_publique_client)

    cle_partagee = pow(cle_publique_serveur, cle_privee, p)

    cle_partagee = str(cle_partagee).encode("utf-8")
    return sha256(cle_partagee).digest()


def send_with_aes(s, message, cle):
    message_chiffre = aes_encrypt(message, cle)
    send_message(s, message_chiffre)

def receive_with_aes(s, cle):
    message_chiffre = receive_message(s)
    if message_chiffre is None:
        print("Erreur : aucun message chiffré reçu.")
        return None

    message_dechiffre = aes_decrypt(message_chiffre, cle)
    return message_dechiffre
