import string
import random
import time
import utile.data as data


# valeurs de simulation
fake_victims = [
    {'HASH': 'b89c7A52daeE6eeebcdfbA2aaD69E5d79dc9BECF8A9D7fD4ae4c83c6EcBca4e1', 'OS': 'Linux',
     'DISKS': '/dev/sdb', 'STATE': 'DECRYPT', 'NB_FILES': 114},
    {'HASH': '5FB1B0Cb07dC45E006aaF11c8D56A5feb506B8f07Ca1C902E3c78B96AbD0E269', 'OS': 'Linux',
     'DISKS': '/dev/sda', 'STATE': 'CRYPT', 'NB_FILES': 3},
    {'HASH': '6494F20Ac77C4De3b9bEfcea46c1B602D2eF0b738FAE9B0721792aB48E2AAA23', 'OS': 'Windows',
    'DISKS': 'E:', 'STATE': 'DECRYPT', 'NB_FILES': 2},
    {'HASH': '1Cbbde736aaaC1991C60d8Fbcfbd0B82ef83C1f5feAB480b6A1BE5fe43e86e32', 'OS': 'MacOS',
     'DISKS': '/dev/disk0', 'STATE': 'CRYPT', 'NB_FILES': 0}

]

fake_histories1 = [
    # table states
    (0, 'b89c7A52daeE6eeebcdfbA2aaD69E5d79dc9BECF8A9D7fD4ae4c83c6EcBca4e1', '2025-02-25 15:05:17', 'CRYPT'),
    (1, 'b89c7A52daeE6eeebcdfbA2aaD69E5d79dc9BECF8A9D7fD4ae4c83c6EcBca4e1', '2025-02-25 15:12:36', 'PENDING'),
    (2, 'b89c7A52daeE6eeebcdfbA2aaD69E5d79dc9BECF8A9D7fD4ae4c83c6EcBca4e1', '2025-02-25 15:17:45', 'CRYPT'),
    (3, 'b89c7A52daeE6eeebcdfbA2aaD69E5d79dc9BECF8A9D7fD4ae4c83c6EcBca4e1', '2025-02-25 15:30:07', 'DECRYPT'),
    # table encrypted
    (0, 'b89c7A52daeE6eeebcdfbA2aaD69E5d79dc9BECF8A9D7fD4ae4c83c6EcBca4e1', '2025-02-25 15:05:17', 0),
    (1, 'b89c7A52daeE6eeebcdfbA2aaD69E5d79dc9BECF8A9D7fD4ae4c83c6EcBca4e1', '2025-02-25 15:17:45', 114),

    #nouveau format|bon format ?
    ('b89c7A52daeE6eeebcdfbA2aaD69E5d79dc9BECF8A9D7fD4ae4c83c6EcBca4e1', 'Linux', '/dev/sdb', 'DECRYPT', 114)

]

fake_histories2 = [
    # table states
    (4, '5FB1B0Cb07dC45E006aaF11c8D56A5feb506B8f07Ca1C902E3c78B96AbD0E269', '2025-02-25 15:34:13', 'CRYPT'),
    (5, '5FB1B0Cb07dC45E006aaF11c8D56A5feb506B8f07Ca1C902E3c78B96AbD0E269', '2025-02-25 15:43:03', 'PENDING'),
    (6, '5FB1B0Cb07dC45E006aaF11c8D56A5feb506B8f07Ca1C902E3c78B96AbD0E269', '2025-02-25 15:56:25', 'CRYPT'),
    #table encrypted
    (2, '5FB1B0Cb07dC45E006aaF11c8D56A5feb506B8f07Ca1C902E3c78B96AbD0E269', '2025-02-25 15:34:13', 0),
    (3, '5FB1B0Cb07dC45E006aaF11c8D56A5feb506B8f07Ca1C902E3c78B96AbD0E269', '2025-02-25 15:56:25', 3),

    #nouveau format|bon format ?
    ('5FB1B0Cb07dC45E006aaF11c8D56A5feb506B8f07Ca1C902E3c78B96AbD0E269', 'Linux', '/dev/sda', 'CRYPT', 3)
]

fake_histories3 = [
    #table states
    (7, '6494F20Ac77C4De3b9bEfcea46c1B602D2eF0b738FAE9B0721792aB48E2AAA23', '2025-02-25 15:59:54', 'CRYPT'),
    (8, '6494F20Ac77C4De3b9bEfcea46c1B602D2eF0b738FAE9B0721792aB48E2AAA23', '2025-02-25 16:05:12', 'PENDING'),
    (9, '6494F20Ac77C4De3b9bEfcea46c1B602D2eF0b738FAE9B0721792aB48E2AAA23', '2025-02-25 16:13:17', 'CRYPT'),
    (10, '6494F20Ac77C4De3b9bEfcea46c1B602D2eF0b738FAE9B0721792aB48E2AAA23', '2025-02-25 16:29:25', 'DECRYPT'),
    # table encrypted
    (4, '6494F20Ac77C4De3b9bEfcea46c1B602D2eF0b738FAE9B0721792aB48E2AAA23', '2025-02-25 15:59:54', 0),
    (5, '6494F20Ac77C4De3b9bEfcea46c1B602D2eF0b738FAE9B0721792aB48E2AAA23', '2025-02-25 16:13:17', 2),

    #nouveau format|bon format ?
    ('6494F20Ac77C4De3b9bEfcea46c1B602D2eF0b738FAE9B0721792aB48E2AAA23', 'Windows', 'E:', 'DECRYPT', 2)

]

fake_histories4 = [
    # table states
    (11, '1Cbbde736aaaC1991C60d8Fbcfbd0B82ef83C1f5feAB480b6A1BE5fe43e86e32', '2025-02-25 16:35:08', 'CRYPT'),
    # table encrypted
    (6, '1Cbbde736aaaC1991C60d8Fbcfbd0B82ef83C1f5feAB480b6A1BE5fe43e86e32', '2025-02-25 16:35:08', 0),

    #nouveau format|bon format ?
    ('1Cbbde736aaaC1991C60d8Fbcfbd0B82ef83C1f5feAB480b6A1BE5fe43e86e32', 'MacOS', '/dev/disk0', 'CRYPT', 0)
]

fake_histories = {
    1: fake_histories1,
    2: fake_histories2,
    3: fake_histories3,
    4: fake_histories4
}


def simulate_key(longueur=0):
    letters = ".éèàçùµ()[]" + string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(longueur))


def simulate_hash(longueur=0):
    letters = string.hexdigits
    return ''.join(random.choice(letters) for i in range(longueur))

def simulate_os():
    os = ['WORKSTATION', 'SERVEUR']
    return random.choice(os)

def simulate_disk():
    disks = ['C:','D:', 'E:', 'F:']
    nb_disque = random.randint(1, len(disks))
    selected_disks = random.sample(disks, nb_disque)
    return ', '.join(selected_disks)

def simulate_etat(indice):
    etat = ['CRYPT', 'PENDING', 'DECRYPT']
    return etat[indice]

def simulate_delai():
    return random.randint(64,1024)

def simulate_nombre_fichier():
    return random.randint(0,128)

## méthode standardisé : CRYPT => PENDING => DECRYPT 1 à 3 états possibles par victime
def main():
    # Ajoute de fausses données dans la BD pour les tests
    timbre_temps = int(time.time())
    con = data.connect_db()
    for i in range(4):
        os = simulate_os()
        fake_hash = simulate_hash(64)
        disk = simulate_disk()
        key = simulate_key(32)
        data.insert_data(con, 'victims', ['OS','hash','disks','key'],[os,fake_hash,disk,key])


        nb_etat = random.randint(1,3)
        for i in range(nb_etat):
            data.insert_data(con, 'states', ['hash_victim', 'datetime', 'state'],
                             [fake_hash, timbre_temps, simulate_etat(i)])
            if i == 0:
                data.insert_data(con, 'encrypted', ['hash_victim', 'datetime', 'nb_files'],
                                 [fake_hash, timbre_temps, 0])

            elif i == 1:
                data.insert_data(con, 'encrypted', ['hash_victim', 'datetime', 'nb_files'],
                                 [fake_hash, timbre_temps,
                                  simulate_nombre_fichier()])

            timbre_temps += simulate_delai()

    print("Simulation terminée")



    exit(0)

if __name__ == '__main__':
     main()
