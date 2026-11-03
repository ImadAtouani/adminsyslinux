# RAPPORT — TP2 : Gestion avancée des utilisateurs et des groupes

**Module** : Administration d'un Linux Server · BTC2 — Jour 2/5
**Environnement** : srv-core (Rocky Linux 9)
**Auteur** : Imad Atouani · **Date** : 03/11/2026

---

## Mission 1 — Comptes, groupes et politique d'authentification

### 1.1 Politique d'authentification (avant la création des comptes)

Un compte hérite de la politique en vigueur à sa création : `login.defs`, `pwquality` et `faillock` sont donc réglés **avant** les `useradd`.

**`/etc/login.defs`** (`configs/login.defs.diff`)

| Directive | Avant | Après | Effet |
|---|---|---|---|
| `PASS_MAX_DAYS` | 99999 | **90** | Le mot de passe expire au bout de 90 jours |
| `PASS_MIN_DAYS` | 0 | **1** | Délai minimal d'un jour entre deux changements |
| `PASS_WARN_AGE` | 7 | **14** | Avertissement 14 jours avant l'expiration |
| `UMASK` | 022 | **027** | Umask de base, appliqué aux sessions via `pam_umask` |

**Qualité des mots de passe** (`configs/50-helios.conf`, `pam_pwquality`)

| Directive | Rôle |
|---|---|
| `minlen = 12` | Longueur minimale de 12 caractères |
| `minclass = 3` | Au moins 3 classes de caractères (minuscules, majuscules, chiffres, symboles) |
| `maxrepeat = 3` | Au plus 3 occurrences consécutives du même caractère |
| `dictcheck = 1` | Rejette les mots présents dans un dictionnaire |
| `usercheck = 1` | Rejette un mot de passe qui contient le nom de l'utilisateur |
| `enforce_for_root` | Applique ces règles aussi à `root` |

**Verrouillage sur échecs** (`configs/faillock.conf`, valeurs actives)

```
audit
deny = 5
fail_interval = 900
unlock_time = 600
```

| Directive | Rôle |
|---|---|
| `deny = 5` | Verrouillage après 5 échecs consécutifs |
| `fail_interval = 900` | Les échecs sont comptés sur une fenêtre de 15 minutes |
| `unlock_time = 600` | Déverrouillage automatique après 10 minutes |
| `audit` | Enregistre les verrouillages dans le journal d'audit |

`pam_faillock` n'est pas actif par défaut. Sur la VM, aucun profil `authselect` n'était sélectionné (`authselect current` : « Aucune configuration n'a été détectée », fichiers PAM `system-auth` et `password-auth` ordinaires, sans ligne `faillock`). Le profil a donc été sélectionné explicitement :

```
$ authselect select sssd with-faillock --force --backup=avant-tp2
$ authselect current
ID du Profil : sssd
Fonctionnalités activées :
- with-faillock
```

### 1.2 Squelette, groupes et comptes

Le squelette `/etc/skel/.bashrc` est modifié **avant** `useradd -m` (sinon les homes n'en héritent pas). Il reçoit `EDITOR=vim`, `HISTSIZE=5000` et `HISTTIMEFORMAT='%F %T '`. Il ne contient **pas** de `umask` : `~/.bashrc` est lu après `/etc/profile.d` et écraserait le umask par groupe de la Mission 2.

| Groupe | GID | Rôle |
|---|---|---|
| `transport` | 5000 | Équipe transport (projet partagé) |
| `telemetry` | 5001 | Analystes et auditeur, accès au journal applicatif |
| `helios-ops` | 5002 | Délégation sudo (Mission 4) |

| Compte | UID | Groupe primaire | Groupes secondaires | Particularité |
|---|---|---|---|---|
| `julien` | 5100 | transport | helios-ops | Chef d'équipe, administrateur du groupe `transport` |
| `nadia` | 5101 | transport | — | Exploitante |
| `tarek` | 5102 | telemetry | transport | Analyste télémétrie |
| `audit-ext` | 5103 | telemetry | — | Auditeur externe, compte expirant le 23/11/2026 |

Les quatre comptes ont reçu `chage -M 90 -m 1 -W 14 -I 7`.

### 1.3 Vérifications

**Expiration du mot de passe** (`captures/chage-julien.txt`)

```
Last password change                    : nov. 02, 2026
Password expires                        : janv. 31, 2027
Password inactive                       : févr. 07, 2027
Account expires                         : never
Minimum number of days between password change    : 1
Maximum number of days between password change    : 90
Number of days of warning before password expires : 14
```

Expiration à 90 jours, avertissement à 14 jours ✔. Le mot de passe est inactif 7 jours après l'expiration (`-I 7`). Le compte `audit-ext` a une expiration de compte au **23/11/2026** (+21 jours) ✔.

**Groupes** (`captures/getent-groupes.txt`)

```
transport:x:5000:tarek,nadia
telemetry:x:5001:
helios-ops:x:5002:julien
```

`getent group` n'affiche que les membres **secondaires**. Julien et Nadia ont `transport` comme groupe primaire ; Nadia apparaît parce que Julien l'a ajoutée avec `gpasswd -a nadia transport`, ce qui démontre sa délégation d'administration (`gpasswd -A julien transport`) sans être root.

**Mot de passe faible refusé** (`su - julien`, puis `passwd`, mot de passe `helios`) :

```
MOT DE PASSE INCORRECT : Le mot de passe comporte moins de 12 caractères
passwd: Erreur de manipulation du jeton d'authentification
```

Le mot de passe est refusé par `pam_pwquality` ✔. Le dernier changement de Julien avait été antidaté d'un jour (`chage -d`), car `PASS_MIN_DAYS=1` interdit sinon tout changement le jour même.

**Verrouillage** : 6 tentatives de `su - nadia` avec un mauvais mot de passe depuis `tarek`.

```
$ faillock --user nadia             (avant reset)
When                Type  Source     Valid
2026-11-02 15:40:09 SVC   su-l           V
2026-11-02 15:40:12 SVC   su-l           V
2026-11-02 15:40:15 SVC   su-l           V
2026-11-02 15:40:18 SVC   su-l           V
2026-11-02 15:40:22 SVC   su-l           V

$ faillock --user nadia --reset ; faillock --user nadia     (après reset)
When                Type  Source     Valid
```

Cinq échecs enregistrés (seuil `deny = 5` atteint), puis liste vidée par `--reset` ✔.

---

## Mission 2 — Bits spéciaux et umask

### 2.1 setgid sur le projet, sticky sur le dépôt

```
$ ls -ld /srv/helios/projets/transport /srv/helios/projets/temoin
drwxrwx---. 2 julien transport 6  2 nov. 15:42 /srv/helios/projets/temoin
drwxrws---. 2 julien transport 6  2 nov. 15:42 /srv/helios/projets/transport
```

`transport/` est en `2770` (le `s` du groupe) ; `temoin/` est le témoin sans setgid.

**Héritage du groupe** (fichiers créés par `nadia` et `tarek`) :

```
/srv/helios/projets/temoin/:
-rw-r-----. 1 nadia transport 0  2 nov. 15:43 x
-rw-r-----. 1 tarek telemetry 0  2 nov. 15:43 y

/srv/helios/projets/transport/:
-rw-r-----. 1 nadia transport 0  2 nov. 15:43 tournee-nadia.csv
-rw-r-----. 1 tarek transport 0  2 nov. 15:43 tournee-tarek.csv
```

Un fichier créé par `tarek` dans `transport/` appartient au groupe **transport** (hérité du répertoire grâce au setgid), alors que dans `temoin/` il appartient à **telemetry** (son groupe primaire) ✔. La preuve se fait avec Tarek : le groupe primaire de Nadia est déjà `transport`, donc `x` et `tournee-nadia.csv` ne les distinguent pas.

**Sticky bit** sur `/srv/helios/depot` (`1777`) :

```
drwxrwxrwt. 2 root root 6  2 nov. 15:45 /srv/helios/depot

$ su - tarek -c 'rm -f /srv/helios/depot/fichier-nadia'
rm: impossible de supprimer '/srv/helios/depot/fichier-nadia': Opération non permise
rc attendu != 0 : 1

$ chmod 0777 /srv/helios/depot
$ su - tarek -c 'rm -f /srv/helios/depot/fichier-nadia'
rc attendu 0 : 0
```

Avec le sticky bit (`t`), seul le propriétaire du fichier (ou celui du répertoire, ou root) peut le supprimer. Sans lui, le droit d'écriture sur le répertoire suffit : `tarek` peut supprimer le fichier de `nadia` ✔.

### 2.2 umask : prédiction et mesure

Règle : mode = mode de base (`666` fichier, `777` répertoire) avec les bits du umask retirés. L'umask effectif de Nadia, avant toute modification de profil, vaut **0027** (il provient de `UMASK 027` dans `login.defs`, via `pam_umask`).

| Cas | umask | Prédit (fichier) | Observé (fichier) | Prédit (répertoire) | Observé (répertoire) |
|---|---|---|---|---|---|
| 1 : umask par défaut | 0027 | `640` | `-rw-r-----` ✔ | `750` | `drwxr-x---` ✔ |
| 2 : `umask 002` | 0002 | `664` | `-rw-rw-r--` ✔ | `775` | `drwxrwxr-x` ✔ |
| 3 : `umask 077` | 0077 | `600` | `-rw-------` ✔ | — | — |

```
0027
drwxr-x---. 2 nadia transport 6  2 nov. 15:57 /tmp/d1
-rw-r-----. 1 nadia transport 0  2 nov. 15:57 /tmp/u1
drwxrwxr-x. 2 nadia transport 6  2 nov. 15:57 /tmp/d2
-rw-rw-r--. 1 nadia transport 0  2 nov. 15:57 /tmp/u2
-rw-------. 1 nadia transport 0  2 nov. 15:57 /tmp/u3
```

Prédictions et observations coïncident. Le groupe affiché est `transport` car c'est le groupe primaire de Nadia (aucun setgid dans `/tmp`).

**Umask collaboratif par groupe** (`configs/helios-umask.sh`, installé dans `/etc/profile.d/` en `0644`) :

```
if id -nG | tr ' ' '\n' | grep -qx transport ; then umask 002 ; else umask 027 ; fi
```

Un membre de `transport` obtient `002` (travail collaboratif : le groupe peut écrire), les autres `027`. Le test `grep -qx` cherche le nom de groupe exact, sans correspondance partielle.

```
$ su - nadia -c 'umask ; touch .../transport/partage.txt ; ls -l .../partage.txt'
0002
-rw-rw-r--. 1 nadia transport 0  2 nov. 15:58 partage.txt

$ su - audit-ext -c 'umask'
0027
```

### 2.3 setuid : inventaire, échec, usage légitime

**Inventaire** (`captures/inventaire-setuid.txt`, pris avant l'installation de `helios-lastlog`) :

```
-rwsr-xr-x root root /usr/bin/chage
-rwsr-xr-x root root /usr/bin/crontab
-rwsr-xr-x root root /usr/bin/gpasswd
-rwsr-xr-x root root /usr/bin/mount
-rwsr-xr-x root root /usr/bin/newgrp
-rwsr-xr-x root root /usr/bin/passwd
-rwsr-xr-x root root /usr/bin/su
-rwsr-xr-x root root /usr/bin/umount
-rwsr-xr-x root root /usr/sbin/grub2-set-bootflag
-rwsr-xr-x root root /usr/sbin/pam_timestamp_check
-rwsr-xr-x root root /usr/sbin/unix_chkpwd
-rwxr-sr-x root tty /usr/bin/write
-rwx--s--x root utmp /usr/libexec/utempter/utempter
-r-xr-sr-x root ssh_keys /usr/libexec/openssh/ssh-keysign
---s--x--x root root /usr/bin/sudo
```

Justification de trois binaires :

| Binaire | Bit | Pourquoi il en a besoin |
|---|---|---|
| `/usr/bin/passwd` | setuid root | Un utilisateur ordinaire doit pouvoir changer son mot de passe, ce qui modifie `/etc/shadow`, lisible et inscriptible par root seul. Le programme tourne en root le temps de cette écriture, et ne modifie que le compte de l'appelant. |
| `/usr/bin/sudo` | setuid root (`---s--x--x`) | Il doit changer d'identité (devenir root ou un autre compte) après avoir vérifié la politique `sudoers`, ce que seul root peut faire. Le mode `--x` pour tous interdit même de lire ou copier le binaire. |
| `/usr/bin/mount` | setuid root | L'appel système `mount` est réservé à root ; le binaire permet à un utilisateur de monter ce que `/etc/fstab` autorise (option `user`). |

Les trois autres bits setgid de la liste (`write`, `utempter`, `ssh-keysign`) donnent un groupe privilégié ciblé (`tty`, `utmp`, `ssh_keys`) plutôt que root : c'est le principe de moindre privilège, repris pour `helios-lastlog`.

**Un script ne peut pas être setuid** (le noyau ignore le bit sur un script interprété) :

```
$ printf '#!/usr/bin/bash\nid\n' > /usr/local/bin/faux-setuid.sh ; chmod 4755 /usr/local/bin/faux-setuid.sh
$ su - nadia -c '/usr/local/bin/faux-setuid.sh'
uid=5101(nadia) gid=5000(transport) groupes=5000(transport) contexte=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

L'`uid` reste `nadia` : le bit setuid n'a eu aucun effet. Le script a été supprimé ensuite.

**Cas légitime : `helios-lastlog`** (`configs/helios-lastlog.c`)

Le journal `/var/log/helios/app.log` est en `0640 root:telemetry` ; `julien` n'est pas dans `telemetry`. Un petit binaire C, installé **setgid telemetry**, lui donne accès à ce seul journal :

```
$ ls -l /usr/local/bin/helios-lastlog
-rwxr-sr-x. 1 root telemetry 17504  2 nov. 16:03 /usr/local/bin/helios-lastlog

$ su - julien -c 'tail -n 3 /var/log/helios/app.log' ; echo "rc attendu != 0 : $?"
tail: impossible d'ouvrir '/var/log/helios/app.log' en lecture: Permission non accordée
rc attendu != 0 : 1

$ su - julien -c '/usr/local/bin/helios-lastlog' ; echo "rc attendu 0 : $?"
2026-11-02T16:02:36+01:00 INFO trame 21 ok
2026-11-02T16:02:36+01:00 INFO trame 22 ok
2026-11-02T16:02:36+01:00 INFO trame 23 ok
2026-11-02T16:02:36+01:00 INFO trame 24 ok
2026-11-02T16:02:36+01:00 INFO trame 25 ok
2026-11-02T16:02:36+01:00 INFO trame 26 ok
2026-11-02T16:02:36+01:00 INFO trame 27 ok
2026-11-02T16:02:36+01:00 INFO trame 28 ok
2026-11-02T16:02:36+01:00 INFO trame 29 ok
2026-11-02T16:02:36+01:00 INFO trame 30 ok
rc attendu 0 : 0
```

`tail` direct est refusé (`rc=1`) ; le binaire renvoie les 10 dernières lignes du journal (`rc=0`) alors que Julien n'est pas membre de `telemetry` ✔.

Pourquoi cette conception :

- **setgid et non setuid root** : l'`egid` devient `telemetry`, ce qui suffit pour lire le journal, tandis que l'`uid` reste celui de l'appelant. Un défaut du programme n'ouvre donc pas un accès root.
- **Programme compilé** : un script setuid/setgid serait ignoré (démonstration ci-dessus).
- **`execle` avec chemin absolu** (`/usr/bin/tail`) et **environnement figé** (`PATH=/usr/bin:/bin`, `IFS` neutre) : aucune injection possible via `PATH` ou `IFS`. L'appelant ne peut passer aucun argument : le fichier et le nombre de lignes sont codés en dur.

---

## Mission 3 — ACL POSIX

### 3.1 Accès nominatif hors du groupe

État initial (`captures/acl-0-initial.txt`) : aucune ACL étendue, `group::rwx` et `other::---`.

Pose de l'ACL pour l'auditeur : `setfacl -R -m u:audit-ext:rX transport` (le `X` majuscule accorde `x` aux seuls répertoires).

```
# file: transport
# owner: julien
# group: transport
# flags: -s-
user::rwx
user:audit-ext:r-x
group::rwx
mask::rwx
other::---

$ ls -ld transport
drwxrws---+ 2 julien transport 75  2 nov. 15:58 transport      ← le « + » signale une ACL

$ su - audit-ext -c 'ls -l .../transport/ ; cat .../transport/tournee-nadia.csv'
-rw-rw-r--+ 1 nadia transport 0  2 nov. 15:58 partage.txt
-rw-r-----+ 1 nadia transport 0  2 nov. 15:43 tournee-nadia.csv
-rw-r-----+ 1 tarek transport 0  2 nov. 15:43 tournee-tarek.csv

$ su - audit-ext -c 'touch .../transport/interdit'
touch: impossible de faire un touch '...': Permission non accordée
rc attendu != 0 : 1
```

L'auditeur, qui n'est pas membre de `transport`, **lit** le répertoire et ses fichiers mais **ne peut pas écrire** ✔.

**Le défaut d'une ACL non héritée.** Un fichier créé après coup n'a pas l'entrée de l'auditeur :

| Création de `nouvelle.csv` par Nadia | Mode | Lecture par `audit-ext` |
|---|---|---|
| `umask 002` (umask de session de Nadia, avec `helios-umask.sh`) | `664` | `rc = 0` (lisible via `other:r`) |
| `umask 027` | `640` | `rc = 1`, `Permission non accordée` |

Avec le umask collaboratif, le fichier est lisible par « other » : l'accès de l'auditeur est alors un effet de bord du umask, non de l'ACL. Avec un umask restrictif, l'ACL ne couvre pas le nouveau fichier et l'auditeur est bloqué.

### 3.2 ACL par défaut

```
$ setfacl -d -m u:audit-ext:r transport
$ setfacl -d -m g:transport:rwx transport
$ setfacl -d -m o::--- transport
```

```
# file: srv/helios/projets/transport
# owner: julien
# group: transport
# flags: -s-
user::rwx
user:audit-ext:r-x
group::rwx
mask::rwx
other::---
default:user::rwx
default:user:audit-ext:r--
default:group::rwx
default:group:transport:rwx
default:mask::rwx
default:other::---
```

Un fichier et un répertoire créés ensuite par Nadia héritent de ces entrées :

```
# file: srv/helios/projets/transport/tournee-j2.csv
# owner: nadia
# group: transport
user::rw-
user:audit-ext:r--
group::rwx          #effective:rw-
group:transport:rwx #effective:rw-
mask::rw-
other::---

# file: srv/helios/projets/transport/semaine-41
# flags: -s-
user::rwx
user:audit-ext:r--
group::rwx
group:transport:rwx
mask::rwx
other::---
default:user::rwx
default:user:audit-ext:r--
default:group::rwx
default:group:transport:rwx
default:mask::rwx
default:other::---

$ su - audit-ext -c 'cat .../transport/tournee-j2.csv'
rc attendu 0 : 0
```

Le fichier créé **après** la pose des ACL par défaut est lisible par `audit-ext` sans action ✔. Le sous-répertoire `semaine-41` hérite à la fois de l'ACL d'accès et de l'ACL par défaut, donc la règle se propage dans l'arborescence. On remarque `#effective:rw-` sur les entrées de groupe : le fichier est créé avec le mode `666 & ~002 = 664`, donc le masque vaut `rw-` et retire le `x` demandé par l'ACL par défaut (même mécanisme qu'en 3.3).

### 3.3 Le piège du masque effectif

Avant et après `chmod g-w` sur `tournee-j2.csv`, après `setfacl -m u:tarek:rwx` :

| | Avant (`captures/mask-avant.txt`) | Après (`captures/mask-apres.txt`) |
|---|---|---|
| `user:tarek` | `rwx` | `rwx  #effective:r-x` |
| `group::` | `rwx` | `rwx  #effective:r-x` |
| `group:transport` | `rwx` | `rwx  #effective:r-x` |
| `mask::` | `rwx` | **`r-x`** |

```
$ su - tarek -c "echo x >> $F"
-bash: ligne 1: .../tournee-j2.csv: Permission non accordée      rc=1

$ setfacl -m m::rwx $F
$ su - tarek -c "echo x >> $F"                                    rc attendu 0 : 0
```

**Ce que `chmod g-w` a réellement modifié.** Sur un fichier qui porte une ACL, les trois bits « groupe » de `chmod` et de `ls -l` ne représentent plus le groupe propriétaire : ils représentent le **masque**. `chmod g-w` n'a donc pas touché à l'entrée `group::rwx` ni à `user:tarek:rwx` : il a retiré le `w` du masque (`rwx` devient `r-x`). Le masque est la limite supérieure des droits de **toutes** les entrées nommées et du groupe propriétaire ; les droits **effectifs** sont l'intersection de chaque entrée avec le masque. Tarek a donc perdu l'écriture alors que son entrée affiche toujours `rwx`, d'où l'échec. `setfacl -m m::rwx` restaure le masque, et avec lui l'écriture. Piège : `ls -l` affiche le masque, et non le groupe propriétaire, ce qui trompe facilement.

### 3.4 Sauvegarder, restaurer, transporter

La sauvegarde est dans `configs/acl-transport-2026-11-02.txt` (`getfacl -R transport`). Elle a servi à restaurer les ACL après `setfacl -R -b` (qui les supprime) avec `setfacl --restore`.

Copies de l'arborescence (`captures/acl-cp.txt`) :

| Commande | Résultat |
|---|---|
| `cp -a transport transport-copie` | **Préserve** les ACL : `user:audit-ext:r-x`, `default:` conservées, propriétaire `julien:transport`, setgid conservé |
| `cp -r transport transport-copie2` | **Ne préserve pas** : propriétaire `root:root`, aucune ACL, `group::r-x` |

`tar --acls --xattrs -czf /root/transport.tgz transport` conserve aussi les ACL (vérifié avec `tar --acls --xattrs -tvf`). Les copies de test ont été supprimées.

---

## Mission 4 — Délégation sudo fine et traçable

### 4.1 Règle restreinte pour `helios-ops` (`configs/90-helios-ops`)

| Élément | Rôle |
|---|---|
| `Cmnd_Alias HELIOS_SVC` | `systemctl start/stop/restart/status helios-collect.service` et `start/stop helios.target`, avec arguments exacts |
| `Cmnd_Alias HELIOS_LOG` | `journalctl -u helios-collect.service *` et `-u helios-archive.service *` (le `*` accepte n'importe quels arguments) |
| `Cmnd_Alias DANGEREUX` | `su`, `sudo`, `passwd root`, `vi`, `vim`, `less`, `find` : binaires qui permettent de sortir vers un shell |
| `Defaults:%helios-ops timestamp_timeout=5` | Le mot de passe est mémorisé 5 minutes |
| `passwd_tries=2` | Deux essais de mot de passe seulement |
| `lecture=always` | Affiche l'avertissement de sudo à chaque session |
| `log_output, iolog_dir=/var/log/sudo-io` | Enregistre les entrées/sorties de la session (rejouables par `sudoreplay`) |
| `logfile=/var/log/sudo-helios.log` | Journal texte dédié |
| `%helios-ops ALL = (root) HELIOS_SVC, HELIOS_LOG` | Les membres peuvent lancer ces commandes en root |
| `%helios-ops ALL = (helios) ls /var/lib/helios, cat /var/lib/helios/telemetry.csv` | Lecture limitée **sous l'identité du compte de service** `helios`, pas root |
| `%helios-ops ALL = !DANGEREUX` | Liste noire supplémentaire |

Validation : `visudo -cf` renvoie « analyse réussie » (`captures/visudo.txt`) :

```
/etc/sudoers.d/90-helios-ops : analyse réussie
/etc/sudoers : analyse réussie
/etc/sudoers.d/90-helios-ops : analyse réussie
/etc/sudoers.d/91-nadia-edition : analyse réussie
```

Fichier installé en `0440 root:root`. Le répertoire `/var/log/sudo-io` est en `0700`.

### 4.2 Vérifier, tracer, rejouer

`sudo -l -U julien` (`captures/sudo-l-julien.txt`) liste `systemctl restart helios-collect.service` et le reste de l'alias, mais pas `systemctl restart sshd` ✔. `tarek` et `audit-ext` « ne sont pas autorisés à exécuter sudo » ; `nadia` n'est pas dans `helios-ops` (voir 4.3 pour sa règle `sudoedit`).

Session interactive de Julien (`sudo` exige un terminal pour le mot de passe) :

| Commande | Résultat |
|---|---|
| `sudo systemctl restart helios-collect.service` | **Autorisé** (mot de passe demandé, message `lecture=always` affiché) ; le journal montre l'arrêt et le redémarrage du service à 16:54:57 |
| `sudo systemctl status helios-collect.service --no-pager` | **Refusé** : « Désolé, l'utilisateur julien n'est pas autorisé à exécuter « /bin/systemctl status helios-collect.service --no-pager » en tant que root » |
| `sudo systemctl restart sshd` | **Refusé** : même message |
| `sudo -u helios cat /var/lib/helios/telemetry.csv \| tail -3` | **Autorisé** (en tant que `helios`) |
| `sudo journalctl -u helios-collect.service -n 5` | **Autorisé** (couvert par le `*`) |
| `su - nadia` puis `sudo -l` | « l'utilisateur nadia ne peut pas utiliser sudo sur localhost » (hors groupe) |

Le refus de `status … --no-pager` est instructif : une règle sans argument superflu correspond **exactement** à la ligne indiquée, et l'option `--no-pager`, absente de la règle, la rend non conforme. À l'inverse, le `*` des règles `journalctl` accepte n'importe quels arguments.

**Traçabilité** : `sudoreplay -l` (`captures/sudoreplay.txt`) contient les sessions de Julien :

```
nov.  2 16:54:57 2026 : julien : TTY=pts/4 ; CWD=/home/julien ; USER=root   ; TSID=000001 ; COMMAND=/usr/bin/systemctl restart helios-collect.service
nov.  2 16:55:46 2026 : julien : TTY=pts/4 ; CWD=/home/julien ; USER=helios ; TSID=000002 ; COMMAND=/usr/bin/cat /var/lib/helios/telemetry.csv
nov.  2 16:55:52 2026 : julien : TTY=pts/4 ; CWD=/home/julien ; USER=root   ; TSID=000003 ; COMMAND=/usr/bin/journalctl -u helios-collect.service -n 5
```

Au moins une session de `julien` est enregistrée ✔, avec l'identité cible (`USER=`) de chaque commande.

### 4.3 Une règle laxiste ne protège rien

Règle temporaire (validée par `visudo -c`, puis supprimée) :

```
nadia ALL=(root) NOPASSWD: /usr/bin/vim /srv/helios/projets/transport/*
```

Évasion de shell (`captures/evasion-vim.txt`) :

```
[nadia@localhost ~]$ sudo vim /srv/helios/projets/transport/tournee-nadia.csv
   (dans vim :  :!/usr/bin/id    puis    :!/usr/bin/bash)
uid=0(root) gid=0(root) groupes=0(root) contexte=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[root@localhost nadia]# id
uid=0(root) gid=0(root) groupes=0(root) contexte=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Nadia obtient un **shell root complet** : restreindre le fichier passé en argument ne sert à rien, puisque vim offre `:!commande`. Il est donc impossible de déléguer sûrement un éditeur, un pager (`less`) ou un outil qui exécute des commandes (`find -exec`). La liste noire `DANGEREUX` de `90-helios-ops` en est la reconnaissance, mais une liste noire est contournable (copie du binaire sous un autre nom, etc.) : la vraie protection est une **liste blanche** de commandes exactes.

**Correction** (`configs/91-nadia-edition`) : `sudoedit`.

```
Defaults:nadia !sudoedit_checkdir
nadia ALL=(root) sudoedit /srv/helios/projets/transport/*
```

Test (`captures/sudoedit.txt`) : même manipulation dans vim (`:!id`) :

```
[nadia@localhost ~]$ SUDO_EDITOR=vim sudoedit /srv/helios/projets/transport/tournee-nadia.csv
   (dans vim :  :!id)
uid=5101(nadia) gid=5000(transport) groupes=5000(transport) contexte=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

`sudoedit` copie le fichier dans un répertoire temporaire, lance l'éditeur **avec les droits de Nadia** (et non ceux de root), puis réécrit le fichier : l'éditeur ne s'exécute jamais en root. Le `:!id` renvoie bien `uid=5101(nadia)` au lieu de `uid=0(root)` avec la règle laxiste : l'évasion de shell ne donne plus rien ✔. `!sudoedit_checkdir` est nécessaire car Nadia peut écrire dans `transport/` (sinon sudoedit refuse d'éditer dans un répertoire modifiable). La règle est validée par `visudo -c` (voir 4.1).

---

## Mission bonus — Audit croisé

Audit du serveur réalisé sur `srv-core` (`captures/audit.txt` : comptes, mots de passe vides, fichiers world-writable, répertoires setgid, ACL, droits sudo, expiration).

Constats généraux : aucun compte sans mot de passe ; le seul fichier world-writable est `/srv/helios/depot` (`drwxrwxrwt`, voulu, avec sticky bit) ; `tarek` et `audit-ext` n'ont aucun droit sudo ; `audit-ext` expire le 23/11/2026.

| # | Constat | Commande de remédiation |
|---|---|---|
| 1 | **Fichiers résiduels de `vim` lancé en root** dans le répertoire partagé : `.tournee-nadia.csv.swp` et `.swo`, propriétaire `root`, lisibles par `audit-ext` via l'ACL. Ils contiennent une copie du contenu édité. | `rm -f /srv/helios/projets/transport/.tournee-nadia.csv.sw?` |
| 2 | **Fichiers antérieurs à l'ACL par défaut mal couverts** : `partage.txt` est lisible par tous (`other::r--`), `nouvelle.csv` n'a pas d'entrée pour `audit-ext`, `tournee-nadia.csv` et `tournee-tarek.csv` n'ont que `group::r--` (le groupe ne peut pas y écrire). | `setfacl -R -m u:audit-ext:rX,g:transport:rwX /srv/helios/projets/transport ; chmod -R o-rwx /srv/helios/projets/transport` |
| 3 | **Règles `journalctl … *` trop larges** : le `*` accepte n'importe quels arguments. Risque : `journalctl` utilise un pager, dont on peut sortir par `!commande` pour obtenir un shell root. | Remplacer par une règle sans joker et sans pager : `/usr/bin/journalctl --no-pager -u helios-collect.service`, puis `visudo -cf /etc/sudoers.d/90-helios-ops` |
| 4 | **`sudoedit` inutile et sensible** : `!sudoedit_checkdir` désactive une protection contre les liens symboliques, alors que Nadia peut déjà modifier ces fichiers par le groupe `transport` et l'ACL, sans sudo. | `rm /etc/sudoers.d/91-nadia-edition && visudo -c` |
| 5 | **Inventaire setuid/setgid non à jour** : `helios-lastlog` (setgid `telemetry`) n'apparaît pas dans l'inventaire pris avant son installation. Sans référence, un binaire privilégié ajouté ne se détecte pas. | `find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%M %u %g %p\n' \| sort > /root/setuid-reference.txt` puis `diff` régulier |

---

## Vérification finale des critères de réussite

| Critère | Résultat |
|---|---|
| `chage -l julien` : expiration à 90 jours, avertissement à 14 jours | ✔ |
| Mot de passe de moins de 12 caractères refusé par `pam_pwquality` | ✔ |
| `faillock --user nadia` liste les échecs, `--reset` déverrouille | ✔ |
| Fichier de `tarek` : groupe `transport` dans `transport/`, `telemetry` dans `temoin/` | ✔ |
| `tarek` ne peut pas supprimer un fichier de `nadia` dans `depot` en `1777` | ✔ |
| `helios-lastlog` en `-rwxr-sr-x` ; `julien` lit le journal par le binaire, `tail` direct refusé | ✔ |
| `ls -ld transport` affiche `+`, `getfacl` montre des entrées `default:` | ✔ |
| Fichier créé après les ACL par défaut lisible par `audit-ext` sans action | ✔ |
| `visudo -c` : analyse réussie pour tout `/etc/sudoers.d/` | ✔ |
| `sudo -l -U julien` liste `restart helios-collect.service`, pas `restart sshd` | ✔ |
| `sudoreplay -l` contient au moins une session de `julien` | ✔ |