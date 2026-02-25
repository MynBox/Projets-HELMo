> **Disclaimer :** L'IA ont été utilisés pour aider à la correction orthographique et à la structuration de ce README afin d'en optimiser la lisibilité. 

Ce projet a été réalisé dans un but pédagogique. Pour se défendre efficacement contre les cybermenaces, il est crucial de comprendre comment elles sont construites et comment opèrent les attaquants ("Offense informs Defense"). 

Ce développement m'a permis d'adopter la perspective d'un attaquant et de transformer mes connaissances théoriques en compétences pratiques et techniques :

### 🔬 1. Anatomie des ransomwares et OpSec de l'attaquant
* **Comportement sur l'hôte :** Développement des routines de parcours d'arborescence sur une machine infectée et ciblage d'extensions spécifiques. 
* **Protection de la charge malveillante :** Compréhension des mécanismes de protection utilisés par les attaquants pour cacher et protéger leurs clés de chiffrement 

### 🔐 2. Cryptographie appliquée 
* **Chiffrement et échange de clés :** Mise en pratique concrète des algorithmes de chiffrement symétrique/asymétrique et des protocoles d'échange de clés (notamment **AES** et **Diffie-Hellman**).
* J'ai pu avoir un vision pratique des notions de cryptographie qu'on avait vu jusqu'au début de ce projet que théoriquement. Cela m'a permis de mieux consolider mes connaissances sur la cryptographie.

### 📡 3. Réseau et Concurrence
* **Programmation réseau bas niveau :** Création de sockets TCP et conception d'headers personnalisés pour structurer la communication entre les machines et serveurs.
* **Gestion de la concurrence :** Implémentation du multithreading et utilisation de verrous/lock pour gérer des connexions simultanées provenant de multiples victimes sans corruption de données.

### ⚙️ 4. Architecture et suivi
* **Gestion des données :** Mise en place et gestion d'une base de données pour assurer le suivi précis des victimes

** ENG **

> **Disclaimer:** AI was used to assist with spell checking and structuring this README to optimize its readability. 

This project was carried out for educational purposes. To defend effectively against cyber threats, it is crucial to understand how they are built and how attackers operate ("Offense informs Defense"). 

This development allowed me to adopt an attacker's perspective and transform my theoretical knowledge into practical and technical skills:

### 🔬 1. Ransomware Anatomy and Attacker OpSec
* **Host Behavior:** Development of directory traversal routines on an infected machine and targeting of specific extensions. 
* **Payload Protection:** Understanding the protection mechanisms used by attackers to hide and protect their encryption keys.

### 🔐 2. Applied Cryptography 
* **Encryption and Key Exchange:** Concrete application of symmetric/asymmetric encryption algorithms and key exchange protocols (notably **AES** and **Diffie-Hellman**).
* I was able to get a practical view of cryptography concepts that we had only seen theoretically until the beginning of this project. This allowed me to better consolidate my knowledge of cryptography.

### 📡 3. Networking and Concurrency
* **Low-level Network Programming:** Creation of TCP sockets and design of custom headers to structure communication between machines and servers.
* **Concurrency Management:** Implementation of multithreading and use of locks to manage simultaneous connections from multiple victims without data corruption.

### ⚙️ 4. Architecture and Tracking
* **Data Management:** Setup and management of a database to ensure precise tracking of victims.
  
---
# UE14-Labo



## Clone project on you laptop

```
git clone https://git.helmo.be/p200040/ue14-labo.git
```

## Rename project as require

UE14-1SX-GroupeY

## Change git url for your project
git remote set-url origin https://git.helmo.be/user/UE14-1SX-GroupeY.git

## Import in pycharm and create a new venv

Bottom right -> Add New Interpreter

## (OPTIONAL) make one branch per student

```
git branch -m "YourName"
```

## Valid and push you work

```
git pull
git add .
git commit -m "Your message"
git push
```

## Don't hesitate to ask questions !

