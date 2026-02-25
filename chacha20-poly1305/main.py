
# This is a sample Python script.

import os
import time

from picture import encrypt_image, decrypt_image


# Press Maj+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


def clean_old_files():
    """
    Supprime tous les fichiers présents dans les dossiers Encrypted et Decrypted
    """
    for dirpath, dirnames, filenames in os.walk('resources\\Encrypted'):
        for filename in filenames:
            os.remove(os.path.join(dirpath, filename))
    for dirpath, dirnames, filenames in os.walk('resources\\Decrypted'):
        for filename in filenames:
            os.remove(os.path.join(dirpath, filename))


def effacer_fichiers():
    """
    Efface les fichiers présents dans les dossiers Encrypted et Decrypted.
    """
    rep = input("\nVoulez-vous vraiment effacer les fichiers présents dans les dossiers Encrypted et Decrypted ?  (o/n) ")
    if rep == 'n':
        return
    else:
        print("\nEffacement des fichiers en cours...")
        try:
            clean_old_files()
            print("Les fichiers ont été effacés avec succès.")
            print("Pour voir les changements dans l'arborescence des répertoires PyCharm, "
                  "appuyez sur Ctrl+Alt+Y (Windows/Linux) ou Cmd+Alt+Y (Mac)")
            time.sleep(3)
        except Exception as e:
            print(f"Erreur lors de l'effacement : {e}")


def choisir_fichier_dans_dossier(dossier):
    """
    Demande à l'utilisateur de choisir un fichier parmi ceux disponibles dans le dossier 'Images'.
    Capture la réponse et renvoie le nom du fichier sélectionné.
    """
    # Vérifier si le dossier existe
    if not os.path.exists(dossier):
        print(f"Le dossier '{dossier}' n'existe pas.")
        return None

    # Lister les fichiers dans le dossier
    fichiers = [f for f in os.listdir(dossier) if os.path.isfile(os.path.join(dossier, f))]

    # Vérifier s'il y a des fichiers dans le dossier
    if not fichiers:
        print(f"Aucun fichier trouvé dans le dossier '{dossier}'.")
        return None

    # Afficher la liste des fichiers
    print("Veuillez choisir un fichier parmi les suivants :")
    for i, fichier in enumerate(fichiers, 1):
        print(f"{i}. {fichier}")

    # Capturer la réponse de l'utilisateur
    choix = input(f"Entrez le numéro correspondant à votre choix (1-{len(fichiers)}) : ")

    # Vérifier si l'entrée est valide
    try:
        choix = int(choix)
        if 1 <= choix <= len(fichiers):
            return fichiers[choix - 1]
        else:
            print(f"Choix invalide. Veuillez entrer un numéro entre 1 et {len(fichiers)}.")
            return choisir_fichier_dans_dossier(dossier)  # Relancer si le choix est invalide
    except ValueError:
        print("Entrée invalide. Veuillez entrer un nombre entier.")
        return choisir_fichier_dans_dossier(dossier)  # Relancer si l'entrée est invalide


def chiffrer_image():
    """
    Chiffre une image sélectionnée par l'utilisateur.
    """
    # Choisir fichier image à chiffrer
    dossier = "resources\\Images"
    fichier_selectionne = choisir_fichier_dans_dossier(dossier)
    if fichier_selectionne is None:
        return

    # Chiffrement
    print(f"\nChiffrement de l'image '{fichier_selectionne}' ...")
    try:
        encrypt_image(os.path.join(dossier, fichier_selectionne))
        print(f"\nL'image '{fichier_selectionne}' a été chiffrée avec succès !")
        print("   Pour voir le fichier dans PyCharm : Ctrl+Alt+Y (Windows/Linux) ou Cmd+Alt+Y (Mac)")
        time.sleep(3)
    except Exception as e:
        print(f"Erreur lors du chiffrement : {e}")


def dechiffrer_image():
    """
    Déchiffrer une image sélectionnée par l'utilisateur.
    """
    # Choisir fichier image à déchiffrer
    dossier = "resources\\Encrypted"
    fichier_selectionne = choisir_fichier_dans_dossier(dossier)
    if fichier_selectionne is None:
        return

    # Déchiffrement
    print(f"\nDéchiffrement de l'image '{fichier_selectionne}' ...")
    try:
        decrypt_image(os.path.join(dossier, fichier_selectionne))
        print(f"\nL'image '{fichier_selectionne}' a été déchiffrée avec succès !")
        print("   Pour voir le fichier dans PyCharm : Ctrl+Alt+Y (Windows/Linux) ou Cmd+Alt+Y (Mac)")
        time.sleep(3)
    except Exception as e:
        print(f"Erreur lors du déchiffrement : {e}")
        print("Vérifiez que la clé et le tag sont corrects.")


def afficher_menu_court():
    """
    Affiche un rappel sdu menu proposant trois choix : effacer les fichiers, chiffrer et déchiffrer.
    Capture le choix de l'utilisateur et exécute l'action correspondante.
    """

    print("\nMenu : 1. Effacer les fichiers - 2. Chiffrer une image - 3. Déchiffrer une image - q. Quitter\n")
    choix = input("Entrer le numéro correspondant à votre choix (1-3) : ").strip()

    # Vérification que le choix est valide
    if choix == "1":
        effacer_fichiers()
    elif choix == "2":
        chiffrer_image()
    elif choix == "3":
        dechiffrer_image()
    elif choix == 'q':
        quit()
    else:
        print("Choix invalide. Veuillez entrer un numéro entre 1 et 3 ou 'q' pour terminer.")
        afficher_menu_court()


def afficher_menu():
    """
    Affiche un menu proposant trois choix : effacer les fichiers, chiffrer et déchiffrer.
    Capture le choix de l'utilisateur et exécute l'action correspondante.
    """
    print("\n" + "=" * 50)
    print("Menu :")
    print("=" * 50)
    print("1. Effacer les fichiers")
    print("2. Chiffrer une image")
    print("3. Déchiffrer une image")
    print("q. Quitter")
    print("=" * 50)
    print()

    choix = input("Veuillez entrer le numéro correspondant à votre choix (1-3) : ").strip()

    # Vérification que le choix est valide
    if choix == "1":
        effacer_fichiers()
    elif choix == "2":
        chiffrer_image()
    elif choix == "3":
        dechiffrer_image()
    elif choix == 'q':
        quit()
    else:
        print("Choix invalide. Veuillez entrer un numéro entre 1 et 3 ou 'q' pour terminer.")
        afficher_menu_court()



# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    afficher_menu()
    while True:
        afficher_menu_court()

