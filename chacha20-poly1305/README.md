# ChaCha20-Poly1305

Projet pédagogique en Python implémentant l’algorithme **ChaCha20-Poly1305 AEAD**, tel que défini dans les RFC 7539 et RFC 8439.

---

# Objectif

Ce projet a pour but :

- de comprendre le fonctionnement interne de l’algorithme ChaCha20 (quarter rounds, colonnes, diagonales, etc.) ;
- d’implémenter l’authentification de message avec Poly1305 ;
- d’intégrer ces deux briques cryptographiques dans la construction AEAD (Authenticated Encryption with Associated Data) ;
- de comparer les résultats avec des vecteurs de test officiels.

---

#  Fonctionnalités

-  **ChaCha20** : chiffrement par flot (génération de keystream, XOR avec le plaintext)  
-  **Poly1305** : calcul du tag d’authentification avec une clé dérivée par ChaCha20  
-  **AEAD ChaCha20-Poly1305** : chiffrement + authentification de données supplémentaires (AAD)  
- Gestion des blocs partiels, padding et longueurs conformément aux RFC  
- Fonctions utilitaires : conversion little/big endian, découpage en blocs, etc.  

---

# Exemple d’utilisation

```python
from chacha20_poly1305 import (
    aead_chacha20_poly1305_encrypt,
    aead_chacha20_poly1305_decrypt,
)

# Clé de 256 bits et nonce de 96 bits
key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
nonce = bytes.fromhex("000000090000004a00000000")

aad = b"donnees-authentifiees"
plaintext = b"Message confidentiel"

# Chiffrement
ciphertext, tag = aead_chacha20_poly1305_encrypt(key, nonce, plaintext, aad)
print("Ciphertext :", ciphertext.hex())
print("Tag        :", tag.hex())

# Déchiffrement + recalcul du tag
decrypted, tag2 = aead_chacha20_poly1305_decrypt(key, nonce, ciphertext, aad)
assert decrypted == plaintext, "Le message déchiffré est incorrect"
assert tag2 == tag, "Échec de l’authentification : le tag ne correspond pas"
