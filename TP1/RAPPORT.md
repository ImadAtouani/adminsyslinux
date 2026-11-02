# RAPPORT — TP1 : Configuration avancée du système Linux

**Module** : Administration d'un Linux Server · BTC2 — Jour 1/5
**Environnement** : srv-core + srv-edge (Rocky Linux 9, Oracle VirtualBox)
**Auteur** : Imad Atouani · **Date** : 02/11/2026

---

## Mission 1 — Services, processus et séquence de démarrage

### 1.1 Temps de démarrage avant / après

Source : `captures/boot-avant.svg` et `captures/boot-apres.svg` (`systemd-analyze plot`).

| Mesure | Avant | Après |
|---|---|---|
| Kernel | 2,218 s | 1,790 s |
| initrd | 5,207 s | 5,458 s |
| Userspace | 1 min 24,743 s | 23,602 s |
| **Total** | **1 min 32,169 s** | **30,851 s** |

Gain : environ **61,3 s (−66 %)**, entièrement dû à l'espace utilisateur.

**Unités les plus pénalisantes**

| Unité | Avant | Après |
|---|---|---|
| `NetworkManager-wait-online.service` | **1 min 0,048 s** | masquée, absente du graphe |
| `kdump.service` | 19,6 s | 20,6 s (inchangé) |
| Unités `.device` (ttyS*, configfs) | environ 6,3 s | environ 6,0 s (inchangé) |

`NetworkManager-wait-online` était de loin l'unité la plus lente : elle attendait que le réseau soit « online » pendant 1 min. `kdump.service` reste le deuxième poste (≈ 20 s) : c'est un candidat à une désactivation ultérieure, mais ce n'était pas demandé.

**Conséquence du `mask`** : `NetworkManager-wait-online` est ce qui rend `network-online.target` fiable. Le masquer retire cette garantie : c'est pourquoi l'unit du collecteur ne déclare que `Wants=network-online.target` (dépendance faible) et non `Requires=`. Ici c'est acceptable : le collecteur ne fait qu'écrire en local (`/var/lib/helios`) et n'a pas besoin du réseau pour démarrer. Pour un service qui dépend vraiment du réseau, il faudrait garder cette unit.

### Unités désactivées ou masquées

| Unité | Action | Justification |
|---|---|---|
| `firewalld.service` | `disable --now` | Désactivé **temporairement** pour ne pas gêner les tests réseau (bond, VLAN, routage). Il sera **réactivé au TP3**. |
| `NetworkManager-wait-online.service` | `mask` | Bloquait le boot pendant 1 min en attendant le réseau, alors que le collecteur n'en a pas besoin pour démarrer. `mask` lie l'unité à `/dev/null` : elle ne peut plus démarrer, même par dépendance (plus fort que `disable`). |

### 1.2 Service `helios-collect.service`

Directives de l'unit (`configs/helios-collect.service`) :

| Directive | Rôle |
|---|---|
| `After=` / `Wants=network-online.target` | Ordonnancement après le réseau, sans en faire une dépendance dure |
| `Type=simple` | Le processus lancé par `ExecStart` est le processus principal (boucle longue durée) |
| `User=helios` / `Group=helios` | Compte système dédié, sans shell (`/sbin/nologin`) : pas de privilèges root |
| `Environment=HELIOS_INTERVAL=15` | Période de collecte par défaut (surchargée par le drop-in) |
| `Restart=on-failure` / `RestartSec=5s` | Redémarrage automatique 5 s après un arrêt anormal (crash, signal) |
| `TimeoutStopSec=20s` | Délai maximal d'arrêt avant `SIGKILL` |
| `NoNewPrivileges=yes` | Interdit au processus et à ses enfants de gagner des privilèges (setuid, etc.) |
| `PrivateTmp=yes` | `/tmp` et `/var/tmp` privés au service |
| `ProtectSystem=strict` | Tout le système de fichiers en lecture seule, sauf `ReadWritePaths=` |
| `ReadWritePaths=/var/lib/helios /var/log/helios` | Seuls répertoires où le service peut écrire |
| `ProtectHome=yes` | `/home`, `/root`, `/run/user` inaccessibles |
| `ProtectKernelTunables=yes` | `/proc/sys`, `/sys` en lecture seule |
| `ProtectControlGroups=yes` | Hiérarchie cgroup en lecture seule |
| `RestrictSUIDSGID=yes` | Interdit de créer des fichiers setuid/setgid |
| `CapabilityBoundingSet=` (valeur vide) | Supprime **toutes** les capabilities Linux : le service ne peut rien faire de privilégié |
| `WantedBy=multi-user.target` | Démarrage automatique au boot |

**Score `systemd-analyze security`**

| Version | Score | Niveau |
|---|---|---|
| Avant durcissement | **9,2** | UNSAFE |
| Après durcissement | **5,3** | MEDIUM |

Gain de 3,9 points. Le « avant » a été mesuré sur une copie temporaire de l'unit sans les directives de durcissement, supprimée ensuite.

**État actuel du service** (`systemctl status`) :

```
helios-collect.service - Collecteur de telemetrie Helios
     Loaded: loaded (/etc/systemd/system/helios-collect.service; enabled; preset: disabled)
    Drop-In: /etc/systemd/system/helios-collect.service.d
             └─override.conf
     Active: active (running) since Mon 2026-11-02 13:57:06 CET
   Main PID: 3390 (helios-collect.)
      Tasks: 2 (limit: 10637)
```

Il est `enabled` et le drop-in est bien pris en compte.

**Preuve de redémarrage automatique** (`kill -9` du MainPID) :

```
$ systemctl show -p MainPID -p NRestarts helios-collect.service
MainPID=3390
NRestarts=0
$ kill -9 "$(systemctl show -p MainPID --value helios-collect.service)" ; sleep 8
$ systemctl show -p MainPID -p NRestarts helios-collect.service
MainPID=4547
NRestarts=1
$ systemctl status helios-collect.service --no-pager | head -5
     Active: active (running) since Mon 2026-11-02 14:20:08 CET; 8s ago
```

Après un `SIGKILL`, systemd a relancé le service avec un nouveau PID (3390 → 4547) et `NRestarts=1` ✔. `Restart=on-failure` couvre la mort par signal (sortie anormale), mais pas un `systemctl stop` volontaire.

### 1.3 Drop-in `override.conf`

L'unit d'origine n'est pas modifiée : le réglage local est dans `helios-collect.service.d/override.conf`.

| Directive | Effet |
|---|---|
| `Environment=HELIOS_INTERVAL=5` | Collecte toutes les 5 s au lieu de 15 s |
| `CPUQuota=20%` | Plafonne le service à 20 % d'un CPU |
| `MemoryMax=96M` | Limite dure de mémoire (cgroup) : 96 × 1024 × 1024 = 100 663 296 octets |
| `IOWeight=50` | Poids E/S réduit (défaut 100) |
| `Nice=5` | Priorité CPU légèrement réduite |

Vérification : `systemctl show -p MemoryMax helios-collect.service` → `MemoryMax=100663296` ✔.
```
CPUQuotaPerSecUSec=200ms
MemoryMax=100663296
Nice=5
```

`CPUQuota=20%` s'affiche `200ms` par seconde ✔.

### 1.4 Target `helios.target` et priorités

`helios.target` : `Requires=` et `After=multi-user.target`, `AllowIsolate=no` (interdit `systemctl isolate helios.target`, qui couperait le reste du système), `WantedBy=multi-user.target`. Le service y est rattaché par `systemctl add-wants`.

```
$ systemctl list-dependencies helios.target
helios.target
● ├─helios-collect.service
● └─multi-user.target
●   ├─auditd.service
●   ├─crond.service
●   ├─helios-collect.service
●   ├─sshd.service
    ...
●   │ ├─paths.target
●   │ │ └─helios-inbox.path
    ...
●   │ └─timers.target
●   │   ├─helios-archive.timer
●   │   └─...
```

`helios-collect.service` apparaît sous `helios.target` (via `add-wants`) et sous `multi-user.target` (via son `[Install]`) ✔. On y voit aussi `helios-archive.timer` et `helios-inbox.path`, activés.

Priorités de processus sur un `sha256sum /dev/zero` (charge CPU artificielle) :

```
$ nice -n 19 sha256sum /dev/zero & NPID=$!
$ ps -o pid,ni,pri,cls,rtprio,comm -p "$NPID"
    PID  NI PRI CLS RTPRIO COMMAND
   4590  19   0  TS      - sha256sum
$ renice -n 5 -p "$NPID" ; ionice -c 2 -n 7 -p "$NPID" ; ionice -p "$NPID" ; chrt -p "$NPID"
4590 (process ID) priorité précédente 19, nouvelle priorité 5
best-effort : priorité 7
stratégie d'ordonnancement actuelle pour le PID 4590 : SCHED_OTHER
priorité de planification actuelle pour le PID 4590 : 0
```

- `nice -n 19` : priorité CPU la plus basse (`NI=19`, classe `TS` = temps partagé, `SCHED_OTHER`).
- `renice -n 5` : priorité CPU modifiée **en cours d'exécution** (19 → 5).
- `ionice -c 2 -n 7` : classe d'E/S « best-effort », niveau 7 (le moins prioritaire de cette classe).
- `chrt -p` : le processus reste en `SCHED_OTHER` avec une priorité temps réel de 0 : il n'est pas en temps réel (`RTPRIO` = `-`).
- `nice`/`ionice` agissent sur la priorité relative ; pour un plafond strict, on utilise `CPUQuota=` dans l'unit, comme pour le collecteur.

---

## Mission 2 — Réseau avancé

### 2.1 Bond active-backup

Configuration (`configs/bond0.txt`) : `mode=active-backup, fail_over_mac=active, miimon=100, primary=enp0s9`, IPv4 `10.42.0.10/24`, `never-default=oui`, IPv6 désactivé.

- `miimon=100` : surveillance du lien toutes les 100 ms.
- `primary=enp0s9` : port préféré (reprend la main quand il revient).
- `fail_over_mac=active` : le bond prend l'adresse MAC du port actif.
- `never-default` : le bond ne porte pas la route par défaut (c'est `enp0s3` qui la porte).

État avant coupure (`captures/bond-avant.txt`) :

```
Bonding Mode: fault-tolerance (active-backup) (fail_over_mac active)
Primary Slave: enp0s9 (primary_reselect always)
Currently Active Slave: enp0s9
enp0s9  : MII Status up, 1000 Mbps, full, Link Failure Count 0
enp0s10 : MII Status up, 1000 Mbps, full, Link Failure Count 0
```

Deux ports `up` et un `Active Slave` : critère respecté ✔.
Le mode 802.3ad (LACP) n'est pas utilisable ici : VirtualBox n'émule pas de commutateur LACP.

### 2.2 Bascule

Coupure du lien par `VBoxManage controlvm srv-core setlinkstate3 off` (`captures/bond-pendant.txt`) :

```
Currently Active Slave: enp0s10
MII Status: up        (bond0)
MII Status: down      (enp0s9, lien coupé)
MII Status: up        (enp0s10)
```

Le port actif est passé de `enp0s9` à `enp0s10`.

**Perte de paquets** (`captures/bond-ping.txt`, ping vers `10.42.0.11`) : 279 séquences affichées, **seule `icmp_seq=30` manque : 1 requête perdue** (critère : 2 au maximum) ✔.

Journal noyau (`journalctl -k | grep -i bond`), extrait de l'initialisation du bond au démarrage :

```
bond0: (slave enp0s10): Enslaving as a backup interface with a down link
bond0: (slave enp0s9): Enslaving as a backup interface with a down link
bond0: (slave enp0s10): link status definitely up, 1000 Mbps full duplex
bond0: (slave enp0s10): making interface the new active one
bond0: active interface up!
bond0: (slave enp0s9): link status definitely up, 1000 Mbps full duplex
bond0: (slave enp0s9): making interface the new active one
```

Au démarrage, `enp0s10` devient d'abord actif, puis `enp0s9` reprend la main parce qu'il est le port `primary`.

### 2.3 VLAN 802.1Q (id 42)

- srv-core : `bond0.42` en `10.42.42.10/24` ; srv-edge : `enp0s9.42` en `10.42.42.11/24`.
- Preuve du marquage (`captures/vlan42-tcpdump.txt`, `tcpdump -nei bond0 'vlan 42'`) : les trames sont en `ethertype 802.1Q (0x8100)` avec `vlan 42`, entre `10.42.42.10` et `10.42.42.11` :

```
13:00:51.993921 08:00:27:91:e6:31 > 08:00:27:63:db:4c, ethertype 802.1Q (0x8100), length 102: vlan 42, p 0, ethertype IPv4 (0x0800), 10.42.42.10 > 10.42.42.11: ICMP echo request, id 3, seq 2, length 64
13:00:51.994760 08:00:27:63:db:4c > 08:00:27:91:e6:31, ethertype 802.1Q (0x8100), length 102: vlan 42, p 0, ethertype IPv4 (0x0800), 10.42.42.11 > 10.42.42.10: ICMP echo reply, id 3, seq 2, length 64
```

La MAC source `08:00:27:91:e6:31` est celle d'`enp0s9`, cohérente avec `fail_over_mac=active`. 5 paquets capturés, 0 perdu ✔.

### 2.4 Routage par règles

Table `142 transport` (`/etc/iproute2/rt_tables`) ; route par défaut de la table via `10.42.42.11` (srv-edge) ; règle de priorité 100 sélectionnant la table pour la source `10.42.42.10`.

`ip rule show` (`captures/routage.txt`) :

```
0:      from all lookup local
100:    from 10.42.42.10 lookup transport proto static
32766:  from all lookup main
32767:  from all lookup default
```

```
$ ip route get 8.8.8.8 from 10.42.42.10
8.8.8.8 from 10.42.42.10 via 10.42.42.11 dev bond0.42 table transport uid 0

$ ip route get 8.8.8.8
8.8.8.8 via 10.0.2.2 dev enp0s3 src 10.0.2.15 uid 0
```

Le trafic issu de l'adresse VLAN transport sort par `bond0.42` via srv-edge, le reste par `enp0s3` ✔. Ces mesures ont été faites **après `systemctl reboot`** : la configuration est persistante ✔ (règle marquée `proto static`, donc gérée par NetworkManager).

---

## Mission 3 — Automatisation

### 3.1 Script `helios-archive.sh` : les cinq règles

| Règle | Mise en œuvre |
|---|---|
| Mode strict | `set -euo pipefail`, `IFS=$'\n\t'`, variables en `readonly` |
| Verrou exclusif | `exec 9>"$LOCK"` + `flock -n 9` (non bloquant, rc=2 si pris) |
| Nettoyage sur sortie | `trap cleanup EXIT` (supprime le répertoire temporaire, journalise le rc), `trap … INT TERM` |
| Journalisation | `logger -t helios-archive -p daemon.<niveau>` vers journald |
| Codes retour explicites | 0 OK · 1 erreur interne · 2 verrou déjà pris · 3 prérequis manquant (gzip ou source illisible) |

Détail utile : le fichier est copié dans un répertoire temporaire, vidé (`: > "$SRC"`), compressé puis installé (`0640 helios:helios`) ; la purge supprime les archives de plus de 14 jours.

### Codes retour observés

| Cas | Attendu | Observé |
|---|---|---|
| Exécution normale | 0 | **0** ✔ |
| Verrou déjà pris | 2 | **2** ✔ |
| Source absente | 3 | **3** ✔ |

Journal de l'exécution normale (734 lignes archivées) :

```
helios-archive[2207]: demarrage
helios-archive[2217]: archive /var/lib/helios/archives/telemetry-20261102-133918.csv.gz (734 lignes)
helios-archive[2221]: purge : 0 archive(s) supprimee(s)
helios-archive[2223]: fin d execution rc=0
```

Journal du cas rc=3 :

```
helios-archive[3385]: source illisible : /var/lib/helios/telemetry.csv
helios-archive[3386]: fin d execution rc=3
```

### 3.2 Timer

`helios-archive.service` : `Type=oneshot`, `ConditionPathExists=/var/lib/helios/telemetry.csv` (pas d'archivage sans source), `Nice=10`, `IOSchedulingClass=idle`.
`helios-archive.timer` : `OnCalendar=*-*-* 02:30:00`, `AccuracySec=1min`, `RandomizedDelaySec=120`, `Persistent=yes`.

```
NEXT                        LEFT     UNIT                 ACTIVATES
Tue 2026-11-03 02:30:32 CET 12h left helios-archive.timer helios-archive.service
```

NEXT cohérent avec 02:30 (décalage de 32 s dû à `RandomizedDelaySec`) ✔.

### Tableau comparatif cron vs timer systemd

| Critère | cron | systemd timer | Observation |
|---|---|---|---|
| Rattrapage après VM éteinte | Aucun : l'exécution manquée est perdue | `Persistent=yes` rattrape au redémarrage | **Observé** : timer de test `OnCalendar=*:0/5`, `RandomizedDelaySec=0`. Dernier déclenchement à 14:30:36, extinction (`poweroff`) à 14:32:19, VM rallumée à 14:43:37 (`uptime -s`). Les échéances de 14:35 et 14:40 ont été manquées, et le timer a lancé l'archivage **à 14:43:45, 8 s après le boot**, avant de reprendre son rythme normal à 14:45:00. Fichier d'état : `/var/lib/systemd/timers/stamp-helios-archive.timer` ✔ |
| Journalisation / corrélation | `journalctl -u crond` : lignes `CMD` / `CMDEND` sans code retour ; la sortie standard part par mail (ici `MAILTO=""`) | `journalctl -u helios-archive.service` et `-t helios-archive` : tout est lié à l'unit | `journalctl -t helios-archive` donne les logs du script avec le rc ✔ ; `systemctl status helios-archive.service` affiche aussi les logs de l'unit, `TriggeredBy` (timer et path) et le temps CPU (44 ms) ✔. **Cron observé** (règle `* * * * *`, `journalctl -u crond`) : `CROND (root) CMD (/usr/local/sbin/helios-archive.sh)` à 14:23:01, puis les logs du script (émis par `logger`) apparaissent **dans le journal de `crond`**, mêlés à ceux des autres tâches, et `CMDEND` ne donne pas le code retour. Avec le timer, l'exécution a sa propre unit (`code=exited, status=0/SUCCESS`) ✔ |
| Expression de dépendances | Aucune | `After=`, `Requires=`, `ConditionPathExists=` | `ConditionPathExists` lu dans l'unit ; l'unit est liée à ses déclencheurs (`TriggeredBy: helios-inbox.path, helios-archive.timer`) ✔ |
| Limitation de ressources | Aucune nativement | `Nice=10`, `IOSchedulingClass=idle`, cgroups | Directives présentes dans l'unit ; pour le collecteur, `systemctl show` confirme `CPUQuotaPerSecUSec=200ms`, `MemoryMax=100663296`, `Nice=5` ✔ |
| Dispersion de la charge | Non | `RandomizedDelaySec=120`, `AccuracySec=1min` | NEXT observé à 02:30:19 puis à 02:30:32 selon la mesure : le délai aléatoire est retiré à chaque (re)chargement du timer, donc l'heure varie ✔ |
| Interrogation de la prochaine exécution | Pas d'équivalent natif | `systemctl list-timers`, `systemd-analyze calendar` | Sortie ci-dessus |

---

## Mission bonus — Path unit

`helios-inbox.path` utilise `PathChanged=/srv/helios/inbox`. `PathExistsGlob` relancerait le service en boucle, puisque le script ne vide pas l'inbox, jusqu'à `unit-start-limit-hit`.
`helios-inbox.path` est actif : il apparaît sous `paths.target` dans `list-dependencies`, et `helios-archive.service` indique `TriggeredBy: helios-inbox.path` et `helios-archive.timer`.

Test du dépôt de fichier :

```
$ touch /srv/helios/inbox/test.csv ; sleep 3
$ journalctl -t helios-archive -n 5 --no-pager
nov. 02 14:21:16 helios-archive[4625]: demarrage
nov. 02 14:21:17 helios-archive[4635]: archive /var/lib/helios/archives/telemetry-20261102-142116.csv.gz (380 lignes)
nov. 02 14:21:17 helios-archive[4639]: purge : 0 archive(s) supprimee(s)
nov. 02 14:21:17 helios-archive[4641]: fin d execution rc=0
```

Le dépôt du fichier a déclenché l'archivage immédiatement (14:21:16) ✔.

---

## Vérification finale des critères de réussite

| Critère | Résultat |
|---|---|
| `systemctl is-enabled helios-collect.service` → `enabled` | ✔ |
| Le service survit à un `kill -9` | ✔ (PID 3390 → 4547, `NRestarts=1`) |
| `MemoryMax=100663296` sans modifier l'unit d'origine | ✔ |
| `list-dependencies helios.target` montre `helios-collect.service` | ✔ |
| Bond : deux ports `MII Status: up` + un `Active Slave` | ✔ |
| Coupure du lien : 2 requêtes perdues au maximum | ✔ (1 perdue) |
| `ip route get … from 10.42.42.10` → `bond0.42` ; sinon → `enp0s3` | ✔ |
| Configuration réseau persistante après `reboot` | ✔ |
| Script : rc=2 (instance en cours) / rc=3 (source absente) | ✔ / ✔ |
| `list-timers` : NEXT cohérent avec 02:30 | ✔ |