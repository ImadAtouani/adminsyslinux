# PROJET — Mise en production du portail de suivi des tournées

| | |
|---|---|
| **Module** | Administration d'un Linux Server — BTC2 |
| **Auteur** | Imad Atouani |
| **Formateur** | Ayoub Benhamdi |
| **Serveur** | srv-core (Rocky Linux 9), test pare-feu depuis srv-edge |
| **Date** | 5 et 6 novembre 2026 |

Toutes les sorties ci-dessous sont copiées du terminal de srv-core (ou de srv-edge quand c'est indiqué). Les fichiers livrés sont dans `configs/`, les sorties longues dans `preuves/`.

---

## 1. Tableau de conformité

| Exigence | Commande de preuve | Résultat | Statut |
|---|---|---|---|
| **E1** Comptes et groupe | `id lea` · `getent passwd lea helios-suivi` · `chage -l lea` | `uid=5104(lea) gid=5003(suivi)` · `helios-suivi` uid 994, `/sbin/nologin`, home `/srv/helios/suivi` · 1 / 90 / 14 jours, inactif au 10 févr. 2027 · aucun groupe `wheel`/`ssh-admins` · pas de `/home/helios-suivi` | Conforme |
| **E2** www, setgid et ACL | `ls -ld` · `getfacl -p` · fichier créé par lea · `runuser -u … --` | `drwxrws---+ root suivi` · `user:zabbix:--x` · `default:other::---` · `index.html` créé avec umask 077 et 000 : `rw-rw----+` groupe `suivi` · `nadia` refusée · `zabbix ls` rc=2, `zabbix stat` OK | Conforme |
| **E3** Script de publication | `helios-suivi-publish.sh` lancé en `helios-suivi` · `python3 -m json.tool` · `journalctl -t` | rc=0 puis rc=2, rc=3, rc=1 provoqués · JSON valide · journal sous le tag `helios-suivi-publish` | Conforme |
| **E4** Units | `systemctl status/show/list-dependencies/list-timers` · `curl` · `systemd-analyze security` · `kill -9` | actif, `MemoryMax=134217728`, `CPUQuotaPerSecUSec=500ms`, sous `helios.target` · `/` et `/etat.json` = 200 · **score 1.2 OK** · redémarré en moins de 4 s après `kill -9` · publication toutes les 2 min | Conforme |
| **E5** Délégation sudo | `visudo -c` · `sudo -l -U lea [cmd]` · essai réel en lea | 4 commandes autorisées, `restart sshd` et `--vacuum-size` refusés (rc=1) · fichier `0440 root:root` | Conforme |
| **E6** Pare-feu | `firewall-cmd --query-port` · `--list-all` · `nft list ruleset` · tests depuis srv-edge | `8080/tcp` dans `internal` uniquement (runtime et permanent) · zone par défaut `drop` · srv-edge : 200 sur 10.42.0.10, échec sur 192.168.56.10 | Conforme |
| **E7** Non-régression | `sshd -T` · `ssh lea@…` · `journalctl -u sshd` · `systemctl is-active` | port 2242, root interdit, mots de passe interdits, `allowgroups ssh-admins` · refus de lea tracé dans le journal · `helios-watch-auth.timer` actif · journald persistant | Conforme |
| **E8** Supervision | `zabbix_get -k helios.suivi.http` / `.age` · `systemctl is-active` · `sar -u` | `200` · `94` (< 300) · `zabbix-agent2` et `sysstat-collect.timer` actifs et enabled · bonus : 2 éléments et 2 déclencheurs déclenchés pour de vrai (§ détail E8) | Conforme, bonus fait |
| **E9** Sauvegarde et restauration | `helios-suivi-backup.sh` · `sha256sum -c` · `tar -tzf` · `list-timers` · deux restaurations | archive + `.sha256` valide · 7 archives conservées · timer 03:15 `Persistent=true` · ACL identiques · `index.html` restauré avec ses ACL | Conforme |
| **E10** Audit (bonus) | `/usr/local/sbin/helios-suivi-audit.sh` | `Bilan : 9/9`, rc=0 · 6 pannes provoquées, toutes détectées, retour à 9/9 · identique après redémarrage | Fait — `preuves/audit.txt` |

---

## 2. Justifications

**(a) Durcissement de `helios-suivi.service`**

Le serveur HTTP n'écrit nulle part : `ProtectSystem=strict` sans aucun `ReadWritePaths`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `NoNewPrivileges`, `CapabilityBoundingSet=` vide, `MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `SystemCallFilter=@system-service` privé de `@privileged @resources`, `UMask=0077`, `IPAddressDeny=any` avec `IPAddressAllow=127.0.0.0/8 10.42.0.0/24`.
Score obtenu : **1.2 OK** (`systemd-analyze security helios-suivi.service`). Le portail répond 200 sur `/` et sur `/etat.json`.
**Aucune directive n'a dû être retirée ni adaptée** : le service a démarré dès le premier essai.
Les `✗` restants sont ceux qui contredisent le rôle du service : `RestrictAddressFamilies=~AF_INET` (il doit écouter en TCP), `PrivateNetwork` (il doit être joignable), `RootDirectory`, `PrivateUsers`, `DeviceAllow` et `IPAddressDeny` (liste d'autorisation non locale, voulue pour le réseau métier). Liste complète dans `preuves/security-helios-suivi.txt`.

**(b) Pourquoi `--x` et pas `r-x` pour `zabbix` sur `www`**

L'agent Zabbix n'a besoin que de lire les métadonnées (`stat`) de `etat.json` : il doit pouvoir *traverser* `www` (`x`), pas le *lister* (`r`). Avec `r-x`, il verrait tous les fichiers du répertoire, ce que la fiche interdit.
Observé sans aucune entrée pour `zabbix` : `stat: impossible d'exécuter statx '/srv/helios/suivi/www/etat.json': Permission non accordée`, et `zabbix_get -k helios.suivi.age` renvoie cette erreur suivie d'une erreur de syntaxe du shell (`opérande attendu`, car la substitution `$(stat …)` est vide).
Observé avec `r-x` : `runuser -u zabbix -- ls /srv/helios/suivi/www` affiche `etat.json  index.html` (rc=0).
Avec `--x` : `ls` est refusé (rc=2), `stat` donne `660` et la sonde répond de nouveau (`15`).

**(c) Le risque d'un joker `*` dans `journalctl`**

Une règle `journalctl -u helios-suivi.service *` autoriserait n'importe quelles options en plus de la commande prévue. Un membre de `suivi` pourrait lancer `journalctl --vacuum-size=1M` (ou `--vacuum-time`) pour **supprimer les journaux de toute la machine**, y compris ceux de `auditd` et de `sshd`, donc effacer les traces d'une intrusion. `--rotate` ou une sortie vers un pager permettent aussi des abus.
Ma règle n'autorise que deux chaînes exactes : `/usr/bin/journalctl -u helios-suivi.service -n 100 --no-pager` et son équivalent pour `helios-suivi-publish.service`. Sudo compare tous les arguments : `sudo -l -U lea /usr/bin/journalctl … --vacuum-size=1M` et `… journalctl --vacuum-size=1M` renvoient rc=1, et l'essai réel en `lea` affiche « Désolé, l'utilisateur lea n'est pas autorisé à exécuter ».

---

## 3. Test de restauration (E9.5)

Archive utilisée : `/srv/helios/archives/suivi/suivi-20261105-121544.tar.gz`.

**(a) Extraction dans un répertoire de test et comparaison des ACL de `www`** — durée : **0,072 s**.

```
[root@srv-core suivi]# time {
>   (cd /srv/helios/archives/suivi && sha256sum -c --quiet "$(basename "$A").sha256")
>   rm -rf /tmp/restore-test; mkdir /tmp/restore-test
>   tar -xzpf "$A" --acls --xattrs --selinux --numeric-owner -C /tmp/restore-test
>   (cd /srv/helios/suivi && find www -print0 | sort -z | xargs -0 getfacl -p) > /tmp/acl-prod.txt
>   (cd /tmp/restore-test/srv/helios/suivi && find www -print0 | sort -z | xargs -0 getfacl -p) > /tmp/acl-test.txt
>   diff -u /tmp/acl-prod.txt /tmp/acl-test.txt && echo "ACL IDENTIQUES"
> }
ACL IDENTIQUES

real    0m0,072s
user    0m0,031s
sys     0m0,030s
```
La comparaison trie les fichiers (`find | sort`) : sans tri, `getfacl -R` les liste dans un ordre différent entre les deux arborescences, ce qui produit un `diff` sans rapport avec les ACL.

**(b) Incident simulé : suppression de `index.html`, restauration de ce seul fichier** — durée de la restauration : **0,007 s**.

```
[root@srv-core suivi]# rm -f /srv/helios/suivi/www/index.html
[root@srv-core suivi]# curl -s http://127.0.0.1:8080/ | grep -iE 'listing|<li>'
<title>Directory listing for /</title>
<h1>Directory listing for /</h1>
<li><a href="etat.json">etat.json</a></li>
[root@srv-core suivi]# time {
>   tar -xzpf "$A" --acls --xattrs --selinux --numeric-owner -C / srv/helios/suivi/www/index.html
> }
real    0m0,007s
[root@srv-core suivi]# getfacl -p /srv/helios/suivi/www/index.html
# file: /srv/helios/suivi/www/index.html
# owner: lea
# group: suivi
user::rw-
user:helios-suivi:rwx           #effective:rw-
group::rwx                      #effective:rw-
mask::rw-
other::---
[root@srv-core suivi]# curl -s http://127.0.0.1:8080/ ; ls -l --time-style=full-iso /srv/helios/suivi/www
Portail de suivi Helios
-rw-rw----+ 1 helios-suivi suivi 184 2026-11-05 12:24:57.509517456 +0100 etat.json
-rw-rw----+ 1 lea          suivi  24 2026-11-05 11:28:21.512837011 +0100 index.html
```
Seul `index.html` a été restauré : propriétaire `lea`, groupe `suivi`, ACL et date d'origine (11:28:21) retrouvés. `etat.json` n'a pas été touché (sa date ne change que par la publication planifiée). Sans `index.html`, le portail répond tout de même 200 en affichant la liste du répertoire.

---

## 4. Mesure sous charge

Charge : `for i in $(seq 2000); do curl -s -o /dev/null http://127.0.0.1:8080/etat.json; done`, avec `sar -u 1 60` lancé en parallèle (`preuves/sar-charge.txt`).

```
== AVANT                                 == APRES
MemoryCurrent=10231808                   MemoryCurrent=10248192
CPUUsageNSec=413192000                   CPUUsageNSec=2943911000
usage_usec 413192                        usage_usec 2943927
nr_throttled 1                           nr_throttled 1
throttled_usec 0                         throttled_usec 0

real    0m22,347s    user 0m8,625s    sys 0m7,185s        (boucle de 2000 curl)
sar -u, pendant la charge : ≈ 19 % user, ≈ 36 % system, ≈ 44 % idle (2 CPU)
sar -u, moyenne sur 60 s  : 6,76 % user, 13,75 % system, 79,39 % idle
```

**Le quota `CPUQuota=50%` n'a pas joué :** le portail a consommé 2,53 s de CPU (2 943 911 000 − 413 192 000 ns) en 22,35 s, soit ≈ 0,11 cœur pour environ 89 requêtes par seconde, bien sous les 0,5 cœur autorisés, et `throttled_usec` est resté à 0 avant comme après.
La charge visible dans `sar` (≈ 56 % occupé sur 2 CPU) vient surtout des 2000 processus `curl` (15,8 s de CPU contre 2,5 s pour le portail). La mémoire du portail est passée de 10,2 à 10,2 Mo (+16 Ko), très loin des 128 M.

---

## 5. Limites connues

- **Liste du répertoire exposée.** Sans `index.html`, `http.server` affiche la liste de `www` (observé pendant l'incident simulé). La commande du service étant imposée, je ne peux pas la désactiver ; avec une journée de plus, je mettrais un reverse proxy ou un serveur qui désactive l'`autoindex`.
- **Pas de HTTPS ni d'authentification.** Le portail est en HTTP simple, limité au réseau métier par le pare-feu et par `IPAddressAllow` dans l'unit.
- **Interface web de Zabbix.** Le port 80 de `work` n'a été ouvert que temporairement (1 heure, runtime uniquement) pour finir l'installation du frontend, parce que `AllowTcpForwarding no` (TP3) empêche le tunnel SSH. Il a été refermé et n'est pas permanent. Le serveur Zabbix et MariaDB restent installés sur srv-core (bonus E8.5).
- **Audit.** Le script lit l'état du système mais ne teste pas le temps de restauration ni la reprise du timer après extinction : cette dernière repose sur `Persistent=true`, testée au TP1. Un défaut d'intermittence (`grep -q` dans un pipeline avec `pipefail` pouvait faire échouer le contrôle `nft` environ une fois sur 20) a été détecté puis corrigé : 15 exécutions successives donnent `9/9`.
- **Sauvegarde.** Elle est locale à srv-core (`/srv/helios/archives`) : une perte du disque emporterait aussi les archives. Avec une journée de plus, j'ajouterais une copie vers un autre serveur et un test de restauration planifié.
- **Sonde âge.** Si `etat.json` est absent, `helios.suivi.age` renvoie une erreur de shell au lieu d'une valeur claire ; une version plus robuste renverrait un nombre très grand.

---

## Annexe — Sorties détaillées par exigence

### E1 — Comptes et groupe

```
[root@srv-core ~]# id lea
uid=5104(lea) gid=5003(suivi) groupes=5003(suivi)
[root@srv-core ~]# getent passwd lea helios-suivi
lea:x:5104:5003:Lea Fabre - responsable suivi des tournees:/home/lea:/bin/bash
helios-suivi:x:994:993:Compte de service portail suivi:/srv/helios/suivi:/sbin/nologin
[root@srv-core ~]# chage -l lea
Last password change                                    : nov. 05, 2026
Password expires                                        : févr. 03, 2027
Password inactive                                       : févr. 10, 2027
Account expires                                         : never
Minimum number of days between password change          : 1
Maximum number of days between password change          : 90
Number of days of warning before password expires       : 14
[root@srv-core ~]# id -nG lea | grep -Ewc 'wheel|ssh-admins'
0
[root@srv-core ~]# ls -d /home/helios-suivi 2>&1
ls: impossible d'accéder à '/home/helios-suivi': Aucun fichier ou dossier de ce type
```

### E2 — Répertoire publié

```
[root@srv-core ~]# ls -ld /srv/helios/suivi/www
drwxrws---+ 2 root suivi 6  5 nov.  11:26 /srv/helios/suivi/www
[root@srv-core ~]# getfacl -p /srv/helios/suivi/www
# file: /srv/helios/suivi/www
# owner: root
# group: suivi
# flags: -s-
user::rwx
user:helios-suivi:rwx
user:zabbix:--x
group::rwx
mask::rwx
other::---
default:user::rwx
default:user:helios-suivi:rwx
default:group::rwx
default:mask::rwx
default:other::---

[root@srv-core ~]# su - lea -c 'umask 077; echo "Portail de suivi Helios" > /srv/helios/suivi/www/index.html'
[root@srv-core ~]# su - lea -c 'umask 000; touch /srv/helios/suivi/www/test-umask.txt'
[root@srv-core ~]# ls -l /srv/helios/suivi/www
-rw-rw----+ 1 lea suivi 24  5 nov.  11:28 index.html
-rw-rw----+ 1 lea suivi  0  5 nov.  11:28 test-umask.txt
[root@srv-core ~]# getfacl -p /srv/helios/suivi/www/index.html
# file: /srv/helios/suivi/www/index.html
# owner: lea
# group: suivi
user::rw-
user:helios-suivi:rwx           #effective:rw-
group::rwx                      #effective:rw-
mask::rw-
other::---

[root@srv-core ~]# runuser -u helios-suivi -- cat /srv/helios/suivi/www/index.html
Portail de suivi Helios
[root@srv-core ~]# runuser -u nadia -- cat /srv/helios/suivi/www/index.html; echo "rc=$?"
cat: /srv/helios/suivi/www/index.html: Permission non accordée
rc=1
[root@srv-core ~]# runuser -u zabbix -- ls /srv/helios/suivi/www; echo "rc=$?"
ls: impossible d'ouvrir le répertoire '/srv/helios/suivi/www': Permission non accordée
rc=2
[root@srv-core ~]# runuser -u zabbix -- stat -c '%n %U:%G %a' /srv/helios/suivi/www/index.html
/srv/helios/suivi/www/index.html lea:suivi 660
```
Les deux fichiers sont créés avec le groupe `suivi` et les mêmes droits, malgré des umask différents (077 et 000) : les ACL par défaut s'appliquent à la place de l'umask. Le fichier est lisible par `helios-suivi` et refusé à `nadia`.

### E3 — Script de publication

```
[root@srv-core ~]# runuser -u helios-suivi -- /usr/local/sbin/helios-suivi-publish.sh; echo "rc=$?"
[info] etat.json publie (mesures=245, derniere=2026-11-05T11:30:51+01:00)
rc=0
[root@srv-core ~]# python3 -m json.tool /srv/helios/suivi/www/etat.json
{
    "genere": "2026-11-05T11:30:52+01:00",
    "hote": "srv-core",
    "derniere_mesure": "2026-11-05T11:30:51+01:00",
    "charge_1min": 0.01,
    "mem_dispo_ko": 1364428,
    "mesures": 245
}
[root@srv-core ~]# ls -l /srv/helios/suivi/www/etat.json
-rw-rw----+ 1 helios-suivi suivi 184  5 nov.  11:30 /srv/helios/suivi/www/etat.json
[root@srv-core ~]# (runuser -u helios-suivi -- flock /srv/helios/suivi/www sleep 15 &) ; sleep 1
[root@srv-core ~]# runuser -u helios-suivi -- /usr/local/sbin/helios-suivi-publish.sh; echo "rc=$?"
[warning] une autre instance tourne deja
rc=2
[root@srv-core ~]# runuser -u nadia -- /usr/local/sbin/helios-suivi-publish.sh; echo "rc=$?"
[err] repertoire non inscriptible: /srv/helios/suivi/www
rc=3
[root@srv-core ~]# echo 'ligne,invalide' > /tmp/bad.csv; chmod 644 /tmp/bad.csv
[root@srv-core ~]# env HELIOS_TELEMETRY=/tmp/bad.csv runuser -u helios-suivi -- /usr/local/sbin/helios-suivi-publish.sh; echo "rc=$?"
[err] horodatage invalide: ligne,invalide
rc=1
[root@srv-core ~]# journalctl -t helios-suivi-publish -n 6 --no-pager
nov. 05 11:30:52 srv-core helios-suivi-publish[3811]: etat.json publie (mesures=245, derniere=2026-11-05T11:30:51+01:00)
nov. 05 11:32:55 srv-core helios-suivi-publish[3932]: une autre instance tourne deja
nov. 05 11:33:24 srv-core helios-suivi-publish[3960]: repertoire non inscriptible: /srv/helios/suivi/www
nov. 05 11:33:36 srv-core helios-suivi-publish[3975]: horodatage invalide: ligne,invalide
[root@srv-core ~]# runuser -u zabbix -- stat -c '%n %U:%G %a' /srv/helios/suivi/www/etat.json
/srv/helios/suivi/www/etat.json helios-suivi:suivi 660
[root@srv-core ~]# ls -a /srv/helios/suivi/www
.  ..  etat.json  index.html
```
Le verrou est pris sur le répertoire `www` lui-même (aucune écriture nécessaire), et le fichier temporaire est créé dans `www` puis renommé (`mv`, atomique) : le script fonctionne donc aussi sous `ProtectSystem=strict` avec `ReadWritePaths=/srv/helios/suivi/www`. Aucun fichier temporaire ne subsiste.

### E4 — Units

```
[root@srv-core ~]# systemctl status helios-suivi.service --no-pager
● helios-suivi.service - Portail de suivi Helios (HTTP 8080)
     Loaded: loaded (/etc/systemd/system/helios-suivi.service; enabled; preset: disabled)
     Active: active (running) since Thu 2026-11-05 11:36:37 CET; 8s ago
   Main PID: 4251 (python3)
     Memory: 9.7M (max: 128.0M available: 118.2M peak: 10.0M)
     CGroup: /system.slice/helios-suivi.service
             └─4251 /usr/bin/python3 -m http.server 8080 --bind 0.0.0.0 --directory /srv/helios/suivi/www
[root@srv-core ~]# curl -s -o /dev/null -w '/ -> %{http_code}\n' http://127.0.0.1:8080/
/ -> 200
[root@srv-core ~]# curl -s -o /dev/null -w '/etat.json -> %{http_code}\n' http://127.0.0.1:8080/etat.json
/etat.json -> 200
[root@srv-core ~]# systemd-analyze security helios-suivi.service --no-pager | tail -n 3
✓ UMask=                                                      Files created by service are accessible only by service's own user by default

→ Overall exposure level for helios-suivi.service: 1.2 OK 🙂
[root@srv-core ~]# systemctl show -p User -p MemoryMax -p CPUQuotaPerSecUSec -p Restart helios-suivi.service
Restart=on-failure
CPUQuotaPerSecUSec=500ms
MemoryMax=134217728
User=helios-suivi
[root@srv-core ~]# systemctl list-dependencies helios.target --no-pager
helios.target
● ├─helios-collect.service
● ├─helios-suivi.service
● └─multi-user.target
(…)
[root@srv-core ~]# systemctl list-timers helios-suivi-publish.timer --no-pager
NEXT                        LEFT     LAST                        PASSED      UNIT                       ACTIVATES
Thu 2026-11-05 11:40:44 CET 59s left Thu 2026-11-05 11:38:44 CET 1min 0s ago helios-suivi-publish.timer helios-suivi-publish.service
[root@srv-core ~]# journalctl -t helios-suivi-publish -n 4 --no-pager
nov. 05 11:36:37 srv-core helios-suivi-publish[4264]: etat.json publie (mesures=313, derniere=2026-11-05T11:36:32+01:00)
nov. 05 11:36:43 srv-core helios-suivi-publish[4288]: etat.json publie (mesures=315, derniere=2026-11-05T11:36:42+01:00)
nov. 05 11:38:44 srv-core helios-suivi-publish[4426]: etat.json publie (mesures=339, derniere=2026-11-05T11:38:43+01:00)
nov. 05 11:40:45 srv-core helios-suivi-publish[4557]: etat.json publie (mesures=363, derniere=2026-11-05T11:40:43+01:00)
[root@srv-core ~]# systemctl show -p MainPID --value helios-suivi.service
4251
[root@srv-core ~]# kill -9 $(systemctl show -p MainPID --value helios-suivi.service)
[root@srv-core ~]# sleep 4
[root@srv-core ~]# systemctl is-active helios-suivi.service
active
[root@srv-core ~]# systemctl show -p MainPID -p NRestarts --value helios-suivi.service
4703
1
[root@srv-core ~]# journalctl -u helios-suivi.service -n 6 --no-pager
nov. 05 11:42:52 srv-core systemd[1]: helios-suivi.service: Main process exited, code=killed, status=9/KILL
nov. 05 11:42:52 srv-core systemd[1]: helios-suivi.service: Failed with result 'signal'.
nov. 05 11:42:54 srv-core systemd[1]: helios-suivi.service: Scheduled restart job, restart counter is at 1.
nov. 05 11:42:54 srv-core systemd[1]: Stopped Portail de suivi Helios (HTTP 8080).
nov. 05 11:42:54 srv-core systemd[1]: Started Portail de suivi Helios (HTTP 8080).
[root@srv-core ~]# ls -l --time-style=long-iso /etc/systemd/system/helios-*.service /etc/systemd/system/helios*.target /etc/systemd/system/helios*.timer
-rw-r--r--. 1 root root  202 2026-11-02 13:42 /etc/systemd/system/helios-archive.service
-rw-r--r--. 1 root root  217 2026-11-02 13:42 /etc/systemd/system/helios-archive.timer
-rw-r--r--. 1 root root  580 2026-11-02 12:33 /etc/systemd/system/helios-collect.service
-rw-r--r--. 1 root root  928 2026-11-05 11:36 /etc/systemd/system/helios-suivi-publish.service
-rw-r--r--. 1 root root  173 2026-11-05 11:36 /etc/systemd/system/helios-suivi-publish.timer
-rw-r--r--. 1 root root 1190 2026-11-05 11:36 /etc/systemd/system/helios-suivi.service
-rw-r--r--. 1 root root  148 2026-11-02 12:40 /etc/systemd/system/helios.target
-rw-r-----. 1 root root  249 2026-11-04 13:00 /etc/systemd/system/helios-watch-auth.service
-rw-r-----. 1 root root  197 2026-11-04 13:00 /etc/systemd/system/helios-watch-auth.timer
```
Le PID passe de 4251 à 4703 après `kill -9` : le portail est de nouveau `active` en moins de 4 secondes (redémarrage planifié 2 s après la mort du processus). Seules les trois units du projet portent la date du jour ; celles des TP1 à TP3 sont inchangées. `helios-suivi-publish.service` ne peut écrire que dans `www` (`ProtectSystem=strict` + `ReadWritePaths=/srv/helios/suivi/www`, voir `configs/units/`).
### E5 — Délégation sudo

```
[root@srv-core ~]# visudo -cf /tmp/PROJET/configs/92-helios-suivi
/tmp/PROJET/configs/92-helios-suivi : analyse réussie
[root@srv-core ~]# install -m 0440 -o root -g root /tmp/PROJET/configs/92-helios-suivi /etc/sudoers.d/92-helios-suivi
[root@srv-core ~]# visudo -c
/etc/sudoers : analyse réussie
/etc/sudoers.d/90-helios-ops : analyse réussie
/etc/sudoers.d/91-nadia-edition : analyse réussie
/etc/sudoers.d/92-helios-suivi : analyse réussie
[root@srv-core ~]# ls -l /etc/sudoers.d/92-helios-suivi
-r--r-----. 1 root root 544  5 nov.  11:46 /etc/sudoers.d/92-helios-suivi
[root@srv-core ~]# sudo -l -U lea
L'utilisateur lea peut utiliser les commandes suivantes sur srv-core :
    (root) /usr/bin/systemctl restart helios-suivi.service, /usr/bin/systemctl status --no-pager helios-suivi.service, /usr/bin/systemctl start helios-suivi-publish.service,
        /usr/bin/journalctl -u helios-suivi.service -n 100 --no-pager, /usr/bin/journalctl -u helios-suivi-publish.service -n 100 --no-pager
[root@srv-core ~]# sudo -l -U lea /usr/bin/systemctl restart helios-suivi.service; echo "rc=$?"
/usr/bin/systemctl restart helios-suivi.service
rc=0
[root@srv-core ~]# sudo -l -U lea /usr/bin/journalctl -u helios-suivi.service -n 100 --no-pager; echo "rc=$?"
/usr/bin/journalctl -u helios-suivi.service -n 100 --no-pager
rc=0
[root@srv-core ~]# sudo -l -U lea /usr/bin/systemctl restart sshd; echo "rc=$?"
rc=1
[root@srv-core ~]# sudo -l -U lea /usr/bin/journalctl -u helios-suivi.service -n 100 --no-pager --vacuum-size=1M; echo "rc=$?"
rc=1
[root@srv-core ~]# sudo -l -U lea /usr/bin/journalctl --vacuum-size=1M; echo "rc=$?"
rc=1
```
Essai réel en `lea` :
```
[lea@srv-core ~]$ sudo systemctl status --no-pager helios-suivi.service | head -5
[sudo] Mot de passe de lea :
● helios-suivi.service - Portail de suivi Helios (HTTP 8080)
     Active: active (running) since Thu 2026-11-05 11:42:54 CET; 5min ago
[lea@srv-core ~]$ sudo systemctl restart helios-suivi.service && echo "restart OK"
restart OK
[lea@srv-core ~]$ sudo systemctl start helios-suivi-publish.service && echo "publish OK"
publish OK
[lea@srv-core ~]$ sudo journalctl -u helios-suivi-publish.service -n 100 --no-pager | tail -3
nov. 05 11:48:55 srv-core systemd[1]: Finished Publication de etat.json (portail de suivi Helios).
[lea@srv-core ~]$ sudo systemctl restart sshd
Désolé, l'utilisateur lea n'est pas autorisé à exécuter « /bin/systemctl restart sshd » en tant que root sur srv-core.
[lea@srv-core ~]$ sudo journalctl -u helios-suivi.service -n 100 --no-pager --vacuum-size=1M
Désolé, l'utilisateur lea n'est pas autorisé à exécuter « /bin/journalctl -u helios-suivi.service -n 100 --no-pager --vacuum-size=1M » en tant que root sur srv-core.
```
Le mot de passe de `lea` est demandé à chaque `sudo` (aucun `NOPASSWD`).

### E6 — Pare-feu

```
[root@srv-core ~]# firewall-cmd --zone=internal --add-port=8080/tcp
success
[root@srv-core ~]# firewall-cmd --permanent --zone=internal --add-port=8080/tcp
success
[root@srv-core ~]# firewall-cmd --zone=internal --query-port=8080/tcp
yes
[root@srv-core ~]# firewall-cmd --permanent --zone=internal --query-port=8080/tcp
yes
[root@srv-core ~]# for z in $(firewall-cmd --get-zones); do echo "== $z"; firewall-cmd --zone=$z --list-ports; firewall-cmd --zone=$z --list-rich-rules; done 2>&1 | grep -B3 8080
== internal
2242/tcp 8080/tcp 10051/tcp
[root@srv-core ~]# firewall-cmd --get-default-zone
drop
[root@srv-core ~]# nft list ruleset | grep 8080
                tcp dport 8080 accept
[root@srv-core ~]# firewall-cmd --zone=internal --list-all
internal (active)
  target: default
  interfaces: bond0 bond0.42
  ports: 10051/tcp 2242/tcp 8080/tcp
  rich rules:
        rule source ipset="helios-blacklist" drop
```
Depuis srv-edge :
```
[sysops@srv-edge ~]$ curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 http://10.42.0.10:8080/etat.json
200
[sysops@srv-edge ~]$ nc -zv -w2 192.168.56.10 8080; echo "rc=$?"
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: No route to host.
rc=1
```
Les ports 2242 et 10051 étaient déjà présents dans `internal` avant le projet (TP précédents). Seul 8080 a été ajouté. La configuration complète de la zone est dans `configs/firewall-internal.txt`.

### E7 — Non-régression de la sécurité

```
[root@srv-core ~]# sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|allowgroups) '
port 2242
permitrootlogin no
passwordauthentication no
allowgroups ssh-admins
[root@srv-core ~]# systemctl is-active helios-watch-auth.timer
active
[root@srv-core ~]# ls -d /var/log/journal; grep -rh '^Storage=' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/ 2>/dev/null; journalctl --disk-usage
/var/log/journal
Storage=persistent
Archived and active journals take up 62.4M in the file system.
[root@srv-core ~]# getenforce
Enforcing
```
Refus de `lea` en SSH, depuis srv-edge :
```
[sysops@srv-edge ~]$ ssh -p 2242 lea@192.168.56.10
*** Serveur Helios Logistique - acces strictement reserve ***
Toute connexion est journalisee.
lea@192.168.56.10: Permission denied (publickey).
```
Ligne correspondante dans le journal de srv-core :
```
[root@srv-core ~]# journalctl -u sshd --since "-30min" --no-pager | grep -iE 'lea|not allowed'
nov. 05 12:00:51 srv-core sshd-session[5952]: User lea from 192.168.56.11 not allowed because none of user's groups are listed in AllowGroups
nov. 05 12:00:51 srv-core sshd-session[5952]: Connection closed by invalid user lea 192.168.56.11 port 47712 [preauth]
```
Sur ce système les processus de `sshd` se nomment `sshd-session` : une recherche par `_COMM=sshd` ne trouve rien, il faut passer par l'unit (`-u sshd`).

### E8 — Supervision

```
[root@srv-core ~]# systemctl enable --now zabbix-agent2 sysstat.service sysstat-collect.timer sysstat-summary.timer
[root@srv-core ~]# getent passwd zabbix
zabbix:x:995:994:Zabbix Monitoring System:/var/lib/zabbix:/sbin/nologin
[root@srv-core ~]# grep -E '^(Server|ServerActive)=' /etc/zabbix/zabbix_agent2.conf
Server=127.0.0.1
ServerActive=127.0.0.1
[root@srv-core ~]# systemctl is-active zabbix-agent2; systemctl is-enabled zabbix-agent2
active
enabled
[root@srv-core ~]# systemctl is-active sysstat-collect.timer; systemctl is-enabled sysstat-collect.timer
active
enabled
[root@srv-core ~]# zabbix_get -s 127.0.0.1 -k agent.ping
1
[root@srv-core ~]# cat /etc/zabbix/zabbix_agent2.d/helios-suivi.conf
UserParameter=helios.suivi.http,/usr/bin/curl -s -o /dev/null --max-time 5 -w '%{http_code}' http://127.0.0.1:8080/etat.json || true
UserParameter=helios.suivi.age,echo $(( $(/usr/bin/date +%s) - $(/usr/bin/stat -c %Y /srv/helios/suivi/www/etat.json) ))
[root@srv-core ~]# zabbix_get -s 127.0.0.1 -k helios.suivi.http
200
[root@srv-core ~]# zabbix_get -s 127.0.0.1 -k helios.suivi.age
94
[root@srv-core ~]# sar -u 1 3
12:06:54        CPU     %user     %nice   %system   %iowait    %steal     %idle
12:06:55        all      0,00      0,00      2,03      0,00      0,00     97,97
12:06:56        all      0,00      0,00      2,02      0,00      0,00     97,98
12:06:57        all      0,00      0,50      2,51      0,00      0,00     96,98
Moyenne :     all      0,00      0,17      2,19      0,00      0,00     97,64
```

**Bonus (E8.5)** — hôte `Zabbix server`, 2 éléments et 2 déclencheurs créés par l'API du frontend, puis déclenchés pour de vrai :
```
[root@srv-core ~]# python3 /root/zbx-bonus.py setup
item helios.suivi.http {'itemids': ['50754']}
item helios.suivi.age {'itemids': ['50755']}
trigger 4 {'triggerids': ['25237']}
trigger 3 {'triggerids': ['25238']}
[root@srv-core ~]# python3 /root/zbx-bonus.py etat
item helios.suivi.age valeur= 2 a 12:58:25
item helios.suivi.http valeur= 200 a 12:58:24
trigger ok prio 3 Portail de suivi : etat.json vieux de plus de 300 s
trigger ok prio 4 Portail de suivi : code HTTP different de 200
```
Déclencheurs : `last(/Zabbix server/helios.suivi.http)<>200` → Haute ; `last(/Zabbix server/helios.suivi.age)>300` → Moyenne.

Portail arrêté à 13:06:39 :
```
[root@srv-core ~]# python3 /root/zbx-bonus.py etat
item helios.suivi.age valeur= 118 a 13:08:25
item helios.suivi.http valeur= 0 a 13:08:24
trigger ok prio 3 Portail de suivi : etat.json vieux de plus de 300 s
trigger PROBLEME prio 4 Portail de suivi : code HTTP different de 200
```
Après redémarrage du portail : `http valeur= 200`, les deux déclencheurs `ok`.

Timer arrêté à 13:13:00 :
```
[root@srv-core ~]# python3 /root/zbx-bonus.py etat
item helios.suivi.age valeur= 448 a 13:19:55
item helios.suivi.http valeur= 200 a 13:19:54
trigger PROBLEME prio 3 Portail de suivi : etat.json vieux de plus de 300 s
trigger ok prio 4 Portail de suivi : code HTTP different de 200
```
Après redémarrage du timer et d'une publication : `age valeur= 60`, les deux déclencheurs `ok`, audit à 9/9.

Captures du frontend (le frontend affiche l'heure en UTC, soit une heure de moins que les sorties du terminal : 12:06:54 correspond à 13:06:54 CET) :
- `preuves/pic1.png` — Tableau de bord : serveur Zabbix en cours d'exécution (7.0.32), 1 hôte disponible.
- `preuves/pic2.png` — Collecte de données → Hôtes → Éléments : les éléments `Helios suivi - age etat.json (s)` (`helios.suivi.age`) et `Helios suivi - code HTTP` (`helios.suivi.http`), intervalle 30 s, avec le déclencheur Haut `last(/Zabbix server/helios.suivi.http)<>200` activé.
- `preuves/pic3.png` — Surveillance → Problèmes : problème de sévérité **Haut** « Portail de suivi : code HTTP different de 200 », état PROBLÈME, 12:06:54 (portail arrêté).
- `preuves/pic4.png` — Surveillance → Problèmes : problème de sévérité **Moyen** « Portail de suivi : etat.json vieux de plus de 300 s » sur l'hôte Zabbix server, état PROBLÈME, 12:17:55 (timer arrêté).

### E9 — Sauvegarde et restauration

```
[root@srv-core ~]# ls -ld /srv/helios/archives 2>&1
ls: impossible d'accéder à '/srv/helios/archives': Aucun fichier ou dossier de ce type
[root@srv-core ~]# install -d -o helios -g helios -m 0750 /srv/helios/archives /srv/helios/archives/suivi
[root@srv-core ~]# ls -ldZ /srv/helios/archives /srv/helios/archives/suivi
drwxr-x---. 3 helios helios unconfined_u:object_r:var_t:s0 19  5 nov.  12:12 /srv/helios/archives
drwxr-x---. 2 helios helios unconfined_u:object_r:var_t:s0  6  5 nov.  12:12 /srv/helios/archives/suivi
[root@srv-core ~]# /usr/local/sbin/helios-suivi-backup.sh; echo "rc=$?"
[info] archive creee: suivi-20261105-121421.tar.gz
rc=0
[root@srv-core suivi]# sha256sum -c suivi-*.tar.gz.sha256
suivi-20261105-121421.tar.gz: Réussi
[root@srv-core suivi]# tar -tzf "$A" | grep -E 'sudoers|zabbix|helios-suivi|www/'
srv/helios/suivi/www/
srv/helios/suivi/www/index.html
srv/helios/suivi/www/etat.json
etc/systemd/system/helios-suivi.service
etc/systemd/system/helios-suivi-publish.service
etc/systemd/system/helios-suivi-publish.timer
etc/systemd/system/helios-suivi-backup.service
etc/systemd/system/helios-suivi-backup.timer
etc/sudoers.d/92-helios-suivi
etc/zabbix/zabbix_agent2.d/helios-suivi.conf
usr/local/sbin/helios-suivi-publish.sh
usr/local/sbin/helios-suivi-backup.sh
```
Rétention (9 exécutions supplémentaires) :
```
[root@srv-core suivi]# ls -1 /srv/helios/archives/suivi | grep -c 'tar.gz$'
7
[root@srv-core suivi]# ls -1 /srv/helios/archives/suivi | grep -c 'sha256$'
7
[root@srv-core suivi]# cd /srv/helios/archives/suivi && sha256sum -c --quiet suivi-*.sha256 && echo "empreintes OK"
empreintes OK
[root@srv-core suivi]# journalctl -t helios-suivi-backup --no-pager | grep supprimee | tail -3
nov. 05 12:15:42 srv-core helios-suivi-backup[7175]: ancienne archive supprimee: suivi-20261105-121523.tar.gz
nov. 05 12:15:43 srv-core helios-suivi-backup[7196]: ancienne archive supprimee: suivi-20261105-121534.tar.gz
nov. 05 12:15:44 srv-core helios-suivi-backup[7222]: ancienne archive supprimee: suivi-20261105-121535.tar.gz
```
Codes retour du script de sauvegarde :
```
[root@srv-core suivi]# HELIOS_BACKUP_DEST=/nonexistent /usr/local/sbin/helios-suivi-backup.sh; echo "rc=$?"
[err] destination non inscriptible: /nonexistent
rc=3
[root@srv-core suivi]# ( flock /srv/helios/archives/suivi sleep 10 & ); sleep 1; /usr/local/sbin/helios-suivi-backup.sh; echo "rc=$?"; sleep 10
[warning] une autre instance tourne deja
rc=2
```
Timer :
```
[root@srv-core suivi]# systemctl enable --now helios-suivi-backup.timer
[root@srv-core suivi]# systemctl list-timers helios-suivi-backup.timer --no-pager
NEXT                        LEFT     LAST PASSED UNIT                      ACTIVATES
Fri 2026-11-06 03:15:00 CET 14h left -    -      helios-suivi-backup.timer helios-suivi-backup.service
[root@srv-core suivi]# systemctl cat helios-suivi-backup.timer | grep -E 'OnCalendar|Persistent'
OnCalendar=*-*-* 03:15:00
Persistent=true
```
`Persistent=true` rattrape une exécution manquée si le serveur était éteint à 03 h 15 (comportement déjà vérifié au TP1 sur le timer de `helios-archive`).

### E10 — Audit de conformité (bonus)

Sortie sur le serveur conforme, après redémarrage complet (`preuves/audit.txt`) :
```
[root@srv-core ~]# /usr/local/sbin/helios-suivi-audit.sh | tee /tmp/PROJET/preuves/audit.txt; echo "rc=${PIPESTATUS[0]}"
[OK] E1 - comptes et groupe
[OK] E2 - repertoire publie (setgid + ACL)
[OK] E3 - script de publication
[OK] E4 - units systemd
[OK] E5 - delegation sudo
[OK] E6 - pare-feu
[OK] E7 - non-regression securite
[OK] E8 - supervision Zabbix/sysstat
[OK] E9 - sauvegarde
Bilan : 9/9
rc=0
```
Pannes provoquées (une par une, avec réparation à chaque fois) :
```
### 1 portail arrete
[KO] E4 - units systemd : portail actif;GET / = 200;GET /etat.json = 200
[KO] E8 - supervision Zabbix/sysstat : helios.suivi.http = 200
Bilan : 7/9
rc=1
### 2 8080 retire du pare-feu (runtime)
[KO] E6 - pare-feu : 8080 internal runtime;regle nft 8080
Bilan : 8/9
rc=1
### 3 etat.json vieux de 10 min
[KO] E4 - units systemd : publish.timer actif+enabled;etat.json recent (<300 s)
[KO] E8 - supervision Zabbix/sysstat : helios.suivi.age < 300
Bilan : 7/9
rc=1
### 4 delegation sudo sur restart sshd
[KO] E5 - delegation sudo : refuse: /usr/bin/systemctl restart sshd
Bilan : 8/9
rc=1
### 5 sauvegarde absente
[KO] E9 - sauvegarde : archive presente;empreinte valide;archive sans srv/helios/suivi/www/;(…)
Bilan : 8/9
rc=1
### 6 empreinte invalide
[KO] E9 - sauvegarde : empreinte valide
Bilan : 8/9
rc=1
### final
Bilan : 9/9
rc=0
```
(La sortie « final » liste neuf lignes `[OK]`.)

### Redémarrage complet (`systemctl reboot`) puis contrôle

```
[root@srv-core ~]# uptime -p
up 1 minute
[root@srv-core ~]# systemctl is-active helios-suivi.service helios-suivi-publish.timer helios-suivi-backup.timer zabbix-agent2 sysstat-collect.timer helios-collect.service helios-watch-auth.timer firewalld
active
active
active
active
active
active
active
active
[root@srv-core ~]# firewall-cmd --zone=internal --list-ports; firewall-cmd --get-default-zone
2242/tcp 8080/tcp 10051/tcp
drop
[root@srv-core ~]# getenforce
Enforcing
[root@srv-core ~]# curl -s http://127.0.0.1:8080/etat.json
{
  "genere": "2026-11-05T13:30:08+01:00",
  "hote": "srv-core",
  "derniere_mesure": "2026-11-05T13:30:06+01:00",
  "charge_1min": 3.91,
  "mem_dispo_ko": 1106668,
  "mesures": 1663
}
[root@srv-core ~]# zabbix_get -s 127.0.0.1 -k helios.suivi.age
73
```
L'audit est à 9/9 avec rc=0 dès la première minute après le démarrage : rien ne dépend d'une commande tapée après le boot.

### SELinux

```
[root@srv-core ~]# getenforce
Enforcing
[root@srv-core ~]# ausearch -m AVC -ts today > /tmp/PROJET/preuves/selinux-avc.txt 2>&1; cat /tmp/PROJET/preuves/selinux-avc.txt | head -20
<no matches>
```
Aucun refus SELinux n'a été enregistré pendant le projet ; SELinux est resté en `Enforcing` du début à la fin. Pour le frontend Zabbix, deux booléens ont été activés (`httpd_can_network_connect_db` et `httpd_can_network_connect`), sans jamais passer en `permissive`.
