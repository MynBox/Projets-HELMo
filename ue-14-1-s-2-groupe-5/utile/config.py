import utile.security as security
import pickle
import os
import base64
import json


# Constante
AES_GCM = True

# Variable globale
config = {}



def load_config(config_file='config/config.cfg', key_file='config/key.bin'):
    """
    Fonction permettant de charger la configuration au format JSON avec cryptage AES-GCM
    :param config_file: (str) Fichier d'enregistrement de la configuration
    :param key_file: (str) Fichier d'enregistrement de la clé de chiffrement AES-GCM
    :return: (dict) La configuration chargée
    """
    global config
    try:
        with open(key_file, 'rb') as kf:
            key = kf.read()
        with open(config_file, 'rb') as cf:
            encrypted_data = pickle.load(cf)
        decrypted_data = security.aes_decrypt(encrypted_data, key)
        config = json.loads(decrypted_data)
    except Exception as e:
        print(f"Erreur lors du chargement de la configuration : {e}")
        config = {}


def save_config(config_file='config/config.cfg', key_file='config/key.bin'):
    """
    Fonction permettant de sauvegarder la configuration au format JSON avec cryptage AES-GCM.
    Si le dossier de configuration n'existe pas, il est créé automatiquement.

    :param config_file: (str) Fichier d'enregistrement de la configuration.
    :param key_file: (str) Fichier d'enregistrement de la clé de chiffrement AES-GCM.
    :return: Néant.
    """
    global config
    key = b''
    if config != {}:
        if AES_GCM:
            key = security.gen_key()
            os.makedirs(os.path.dirname(key_file), exist_ok=True)  # Crée le dossier "config" s'il n'existe pas
            with open(key_file, 'wb') as k:
                k.write(key)

        data = json.dumps(config)

        if AES_GCM:
            data = security.aes_encrypt(data, key)
        data = pickle.dumps(data)

        os.makedirs(os.path.dirname(config_file), exist_ok=True)  # Assure que le dossier "config" existe
        with open(config_file, 'wb') as c:
            c.write(data)

def get_config(setting):
    """
    Renvoie la valeur de la clé de configuration chargée en mémoire (voir fonction load_config ou
    configuration en construction)
    :param setting: (str) clé de configuration à retourner
    :return: valeur associée à la clé demandée
    """
    return config.get(setting, None)

def set_config(setting, value):
    """
    Initialise la valeur de la clé de configuration chargée en mémoire (voir fonction load_config ou
    configuration en construction)
    :param setting: (str) clé de configuration à retourner
    :param value: Valeur à enregistrer
    :return: Néant
    """
    config[setting] = value

def print_config():
    """
    Affiche la configuration en mémoire
    :return: Néant
    """
    print(json.dumps(config, indent=4))

def reset_config():
    """
    Efface la configuration courante en mémoire
    :return: Néant
    """
    global config
    config = {}

def remove_config(setting):
    """
    Retire une paire de clé (setting) / valeur de la configuration courante en mémoire
    :param setting: la clé à retirer de la config courante
    :return: Néant
    """
    config.pop(setting, None)

def validate(msg):
    """
    Demande de confirmation par O ou N
    :param msg: (str) Message à afficher pour la demande de validation
    :return: (boolean) Validé ou pas
    """
    while True:
        choice = input(f"{msg} (O/N) : ").strip().lower()
        if choice in ['o', 'n']:
            return choice == 'o'
        print("Veuillez entrer 'O' pour oui ou 'N' pour non.")
