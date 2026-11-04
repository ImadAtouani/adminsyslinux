# RAPPORT — TP3 : Sécurisation d'un serveur Linux

**Module** : Administration d'un Linux Server · BTC2 — Jour 3/5
**Environnement** : srv-core (cible) + srv-edge (poste distant : administrateur et attaquant), Rocky Linux 9
**Auteur** : Imad Atouani · **Dates** : 04/11/2026

---

## Mission 1 — Pare-feu firewalld segmenté par zone

### 1.1 Remise en service et état des lieux

`firewalld` désactivé au TP1 est réactivé (`unmask` puis `enable --now`). Avant toute affectation, aucune connexion NetworkManager ne portait de zone (`captures/zones-avant.txt`) : toutes les interfaces retombaient dans la zone par défaut (`public`).

```
enp0s3 :     bond0 :     bond0.42 :     enp0s8 :     bond0-p1 :     bond0-p2 :     lo :
```

### 1.2 Interface → zone → politique

La zone est écrite dans le profil NetworkManager (`connection.zone`) et non dans `firewalld`, puis les connexions sont réactivées. Les noms de connexion détectés sont `enp0s3` (NAT) et `enp0s8` (administration). La zone par défaut passe à `drop`.

| Interface | Connexion | Zone | Politique voulue | Justification |
|---|---|---|---|---|
| `enp0s3` (NAT / Internet) | `enp0s3` | **drop** | Rien n'entre | Côté Internet, aucun service ne doit être joignable ; `drop` ne répond même pas, ce qui limite la détection du serveur par un scan. Le trafic sortant (mises à jour) reste possible grâce au suivi d'état. |
| `enp0s8` (administration) | `enp0s8` | **work** | SSH uniquement, débit limité | Réseau d'administration de confiance relative : SSH seul, limité en débit contre le brute force. La zone est liée à la source `192.168.56.0/24`. |
| `bond0` (métier) | `bond0` | **internal** | SSH + supervision | Réseau interne `10.42.0.0/24` : SSH et le port Zabbix `10051/tcp` (TP4) ; les services superflus du profil par défaut (`mdns`, `samba-client`, `cockpit`, `dhcpv6-client`) sont retirés. |
| `bond0.42` (VLAN transport) | `bond0.42` | **internal** | Idem | Même politique que le réseau métier. |

Zones actives obtenues juste après l'affectation (`captures/zones-actives.txt`) :

```
drop      : enp0s3
internal  : bond0 bond0.42
public    : enp0s10 enp0s9
work      : enp0s8
```

Après `firewall-cmd --set-default-zone=drop`, les deux ports du bond (`enp0s9`, `enp0s10`) passent dans la zone par défaut `drop` (état final) : ce sont des ports esclaves, sans adresse IP, dont le trafic est traité par `bond0` (zone `internal`). Ils ne portent donc aucun service.

### 1.3 Ouvrir le strict nécessaire

État intermédiaire, avant les règles riches (`captures/zone-work.txt`, `zone-internal.txt`) :

```
work (active)                                  internal (active)
  interfaces: enp0s8                             interfaces: bond0 bond0.42
  sources: 192.168.56.0/24                       services: ssh
  services: ssh                                  ports: 10051/tcp
```

### 1.4 Règles riches, limitation, liste de blocage

État final de toutes les zones (`configs/zones.txt`, extrait des zones actives) :

```
drop (active)      target: DROP     interfaces: enp0s10 enp0s3 enp0s9
internal (active)  interfaces: bond0 bond0.42
                   ports: 10051/tcp 2242/tcp
                   rich rules: rule source ipset="helios-blacklist" drop
work (active)      interfaces: enp0s8      sources: 192.168.56.0/24      services: (aucun)
                   rich rules:
                     rule port port="10051" protocol="tcp" reject
                     rule source ipset="helios-blacklist" drop
                     rule port port="2242" protocol="tcp" log prefix="SSH-NEW " level="info" limit value="3/m" accept limit value="6/m"
```

(le service `ssh` a été remplacé par le port 2242 lors de la Mission 2.)

| Règle | Effet |
|---|---|
| `log prefix="SSH-NEW " … limit 3/m` + `accept limit 6/m` | Journalise les nouvelles connexions SSH (3 par minute) et en accepte 6 par minute : frein au brute force |
| `port 10051/tcp reject` sur `work` | Le port Zabbix est refusé explicitement hors du réseau métier |
| `source ipset="helios-blacklist" drop` (work et internal) | Abandonne tout paquet venant d'une adresse de la liste de blocage |
| `--new-ipset=helios-blacklist` (`hash:ip`, `family=inet`, `hashsize=4096`, `maxelem=65536`) | Liste de blocage alimentée automatiquement par la Mission 3 |
| `--set-log-denied=unicast` | Journalise les paquets unicast refusés par le pare-feu |

### 1.5 Ce que firewalld a réellement écrit dans nftables

`nft list chain inet firewalld filter_IN_work` (`captures/nft.txt`) : la chaîne ne contient que des `jump` vers des sous-chaînes, puis les règles de sortie :

```
chain filter_IN_work {
    jump filter_INPUT_POLICIES_pre
    jump filter_IN_work_pre
    jump filter_IN_work_log
    jump filter_IN_work_deny
    jump filter_IN_work_allow
    jump filter_IN_work_post
    jump filter_INPUT_POLICIES_post
    meta l4proto { icmp, ipv6-icmp } accept
    meta pkttype host log prefix "filter_IN_work_REJECT: "
    reject with icmpx admin-prohibited
}
```

Les règles riches sont dans les sous-chaînes (`captures/nft-chaines.txt`) :

```
chain filter_IN_work_allow { tcp dport 2242 limit rate 6/minute burst 5 packets accept }
chain filter_IN_work_deny  { tcp dport 10051 reject
                             ip saddr @helios-blacklist drop }
chain filter_IN_work_log   { tcp dport 2242 limit rate 3/minute burst 5 packets log prefix "SSH-NEW " level info }
set helios-blacklist       { type ipv4_addr  size 65536  flags interval }
```

- L'ordre `log` → `deny` → `allow` explique le comportement : l'`ipset` et le `reject` sont évalués **avant** l'acceptation limitée.
- Le « 6/m » est implémenté par `limit rate 6/minute burst 5 packets` : une rafale de 5 connexions passe, puis une nouvelle toutes les 10 s. C'est pourquoi les tests SSH de la Mission 2 sont espacés.
- La cible par défaut de la zone est `reject with icmpx admin-prohibited` (`No route to host` côté client) ; l'ICMP reste accepté.
- `iptables -S` ne montre que les politiques `ACCEPT` : `iptables` n'est qu'une couche de compatibilité (`iptables-nft`) ; le filtrage réel est dans la table `inet firewalld`.

**Scans nmap depuis srv-edge** (`captures/nmap-avant.txt`, `nmap-apres.txt`) :

| Port | Avant (pare-feu arrêté) | Après |
|---|---|---|
| 22/tcp | open | open (accepté dans la limite du débit) |
| 80/tcp | closed | **filtered** (rejet par défaut `admin-prohibited`) |
| 10051/tcp | closed | closed (règle explicite `reject`, réponse TCP RST) |

`nc -zv -w 2 192.168.56.10 10051` : `Connection refused`, `rc attendu != 0 : 1` ✔.
Boucle de 12 connexions vers le port 22 : les premières aboutissent (`Connected`), puis les suivantes sont refusées (`No route to host`) ou sans réponse (`TIMEOUT`, probablement la limitation de débit des réponses ICMP du noyau).

**Traces dans le journal noyau** (`captures/ssh-new.txt`, `denied.txt`) :

```
kernel: SSH-NEW IN=enp0s8 SRC=192.168.56.11 DST=192.168.56.10 PROTO=TCP SPT=59968 DPT=22 SYN
  (5 lignes SSH-NEW d'affilée, soit la rafale du limiteur de journalisation)
kernel: filter_IN_work_REJECT: IN=enp0s8 SRC=192.168.56.11 DST=192.168.56.10 PROTO=TCP DPT=22 SYN
  (puis les connexions refusées une fois la limite dépassée ; le port 80 est lui aussi journalisé)
```

---

## Mission 2 — Durcissement de sshd

### 2.1 Accès par clé avant de couper le mot de passe

Groupe de service `ssh-admins` (`sysops`, `julien`). Clé `ed25519` (`-a 100`) générée sur srv-edge et copiée par `ssh-copy-id` ; une clé du poste d'administration est aussi installée avant la coupure du mot de passe. `authorized_keys` est en `0600 sysops:sysops` (`captures/hostkeys.txt`).

Empreintes des clés d'hôte de srv-core :

```
256  SHA256:Aom0GBNT1mlRDceYgBz1QMm9KDA/hbSM5i53JMXMFj4  (ECDSA)
256  SHA256:9APHH3cgFn/SKBkFzNzQVAykoY4KaliANF9cY0+7G5g  (ED25519)
3072 SHA256:7Bv8/3GXAsfWaNJ9ba21pKYt0fN/2isWMQx4SZYJGQg  (RSA)
```

### 2.2 Fichier de surcharge `10-helios-hardening.conf`

`/etc/ssh/sshd_config` commence par `Include /etc/ssh/sshd_config.d/*.conf` : le drop-in l'emporte sur le fichier principal.

| Directive | Rôle |
|---|---|
| `Port 2242` | Sort du port 22 standard, ce qui réduit le bruit des scans automatiques (ce n'est pas une protection en soi) |
| `AddressFamily inet` | IPv4 uniquement |
| `ListenAddress 192.168.56.10` / `10.42.0.10` | Écoute seulement sur l'interface d'administration et le réseau métier, jamais sur le NAT |
| `PermitRootLogin no` | Pas de connexion root directe |
| `PubkeyAuthentication yes` | Authentification par clé |
| `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `PermitEmptyPasswords no` | Plus aucune authentification par mot de passe |
| `AuthenticationMethods publickey` | Impose la clé comme **seule** méthode acceptée |
| `MaxAuthTries 3` | 3 essais par connexion |
| `MaxSessions 4` | 4 sessions par connexion |
| `MaxStartups 10:30:60` | À partir de 10 connexions non authentifiées, 30 % sont refusées, 100 % à 60 |
| `LoginGraceTime 30` | 30 s pour s'authentifier |
| `AllowGroups ssh-admins` | Seuls les membres de ce groupe peuvent se connecter |
| `X11Forwarding no`, `AllowAgentForwarding no`, `AllowTcpForwarding no`, `AllowStreamLocalForwarding no`, `PermitTunnel no`, `GatewayPorts no` | Aucune redirection ni tunnel par défaut |
| `PermitUserEnvironment no` | Interdit à l'utilisateur de modifier l'environnement de sshd |
| `ClientAliveInterval 300`, `ClientAliveCountMax 2` | Coupe les sessions inactives après environ 10 minutes sans réponse |
| `TCPKeepAlive no` | Pas de keepalive TCP, falsifiable ; seul le keepalive SSH chiffré est utilisé |
| `LogLevel VERBOSE` | Journalise l'empreinte de la clé utilisée et les refus détaillés |
| `PrintLastLog yes` | Affiche la dernière connexion |
| `Banner /etc/issue.net` | Bandeau d'avertissement légal (`configs/issue.net`) |
| `Subsystem sftp internal-sftp -l INFO -f AUTHPRIV` | SFTP interne au processus, journalisé |
| `Match Group helios-ops` : `AllowTcpForwarding yes`, `PermitOpen localhost:10051` | Exception maîtrisée : l'équipe d'exploitation peut ouvrir un tunnel, seulement vers le port 10051 |

La syntaxe est vérifiée par `sshd -t` avant chaque rechargement. Un `Match` capte toutes les directives qui le suivent : c'est pourquoi les directives de chiffrement ne peuvent pas être ajoutées en fin de ce fichier.

### 2.3 Algorithmes : crypto-policies et `sshd_config`

Sur RHEL/Rocky 9, `sshd` retient la **première** valeur lue pour chaque mot-clé. `/etc/ssh/sshd_config.d/50-redhat.conf` inclut `/etc/crypto-policies/backends/opensshserver.config`, qui fixe les algorithmes de la politique système. Les fichiers de `sshd_config.d` sont lus par ordre alphabétique : `05-helios-crypto.conf` est lu **avant** `50-redhat.conf`, donc ses valeurs l'emportent ; placé après, il serait ignoré. Les directives `Ciphers`, `KexAlgorithms`, `MACs` et `HostKeyAlgorithms` doivent aussi se trouver hors de tout bloc `Match`.

**(a) Politique système durcie** : `update-crypto-policies --set DEFAULT:NO-SHA1` (`captures/sshd-T-policy.txt`, extrait) :

```
ciphers aes256-gcm@openssh.com, chacha20-poly1305@openssh.com, aes256-ctr, aes128-gcm@openssh.com, aes128-ctr
macs    hmac-sha2-256-etm@openssh.com, hmac-sha1-etm@openssh.com, umac-128-etm@openssh.com, hmac-sha2-512-etm@openssh.com, hmac-sha2-256, hmac-sha1, umac-128@openssh.com, hmac-sha2-512
kexalgorithms curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256/384/521, diffie-hellman-group-exchange-sha256, diffie-hellman-group14-sha256 …
```

Le sous-profil `NO-SHA1` désactive SHA-1 dans les signatures (le journal le confirme : `SHA1 in signatures is disabled for RSA keys`), mais les MACs `hmac-sha1*` et les courbes NIST restent proposés.

**(b) Surcharge locale** `05-helios-crypto.conf` (`captures/sshd-T-crypto.txt`) :

```
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
kexalgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
```

Listes réduites à quelques algorithmes forts (chiffrement authentifié, MACs SHA-2 « encrypt-then-MAC », échange de clés Curve25519 ou DH 4096 bits). La liste de `HostKeyAlgorithms` est limitée à `ssh-ed25519,rsa-sha2-512`.

### 2.4 Changement de port : SELinux et pare-feu

Mise en œuvre dans l'ordre suivant, pour ne pas se couper l'accès : SELinux, puis pare-feu, puis redémarrage de `sshd`.

```
$ semanage port -l | grep ssh_port_t
ssh_port_t                     tcp      2242, 22
```

Pare-feu : règle riche avec journalisation et limitation sur le port 2242 dans `work`, `2242/tcp` ouvert dans `internal`, anciens `ssh` retirés, puis `firewall-cmd --reload`.

`sshd` écoute uniquement sur les deux adresses prévues (`captures/ss-sshd.txt`) :

```
LISTEN  10.42.0.10:2242      users:(("sshd",pid=17936,fd=7))
LISTEN  192.168.56.10:2242   users:(("sshd",pid=17936,fd=8))
```

**Les trois conséquences d'un changement de port SSH sur RHEL 9**

1. **SELinux** : `sshd` ne peut se lier qu'à un port de type `ssh_port_t` ; sans `semanage port -a -t ssh_port_t -p tcp 2242`, `sshd` refuse de démarrer sur 2242 (refus AVC).
2. **Pare-feu** : le service `ssh` de firewalld ouvre le port 22 ; le port 2242 doit être ouvert explicitement dans chaque zone concernée (règle riche dans `work`, port dans `internal`), et l'ancienne ouverture retirée.
3. **Clients et outils** : `ssh -p 2242`, `scp -P 2242`, une entrée `known_hosts` distincte par port, les scripts et la supervision à mettre à jour, ainsi que la règle de limitation de débit du pare-feu.

### 2.5 Les sept tests depuis srv-edge

`captures/tests-ssh.txt` et traces serveur `captures/sshd-refus.txt` (`LogLevel VERBOSE`).

| # | Test | Résultat attendu | Observé | Ligne de journal serveur |
|---|---|---|---|---|
| 1 | `nc 192.168.56.10 22` | Échec | `No route to host` (1) ✔ | Aucune ligne `sshd` : le port 22 n'est plus ouvert dans le pare-feu (`No route to host` = rejet `admin-prohibited`) et `sshd` n'y écoute plus |
| 2 | `ssh -p 2242 sysops@…` (clé) | Succès | `localhost.localdomain` / `sysops wheel ssh-admins` (0) ✔, bandeau affiché | `Accepted publickey for sysops from 192.168.56.11 port 54502 ssh2: ED25519 SHA256:zJx8…` |
| 3 | `ssh -p 2242 root@…` | Refus | `Permission denied (publickey)` (255) ✔ | `User root from 192.168.56.11 not allowed because none of user's groups are listed in AllowGroups` |
| 4 | Mot de passe seul | Refus | `Permission denied (publickey)` (255) ✔ | `Connection closed by authenticating user sysops 192.168.56.11 port 54518 [preauth]` (aucune méthode par mot de passe n'est proposée) |
| 5 | `nadia@…` (hors `ssh-admins`) | Refus | `Permission denied (publickey)` (255) ✔ | `User nadia from 192.168.56.11 not allowed because none of user's groups are listed in AllowGroups` |
| 6 | Tunnel `-L 9999:localhost:10051` | Trafic refusé | `channel 2: open failed: administratively prohibited` ✔ | Connexion de `sysops` acceptée puis fermée ; `sysops` n'est pas dans `helios-ops`, donc `AllowTcpForwarding no` |
| 7 | KEX `diffie-hellman-group14-sha1` | Échec | `Unable to negotiate … no matching key exchange method found` (255) ✔ | `Unable to negotiate with 192.168.56.11 port 33202: no matching key exchange method found. Their offer: diffie-hellman-group14-sha1,…` |

À noter :
- Le test 6 : `Connected to 127.0.0.1:9999` ne prouve rien (c'est le client SSH local qui écoute) ; la preuve est `administratively prohibited`, qui n'apparaît qu'à l'usage du tunnel.
- Test 7 : l'offre du serveur (`curve25519-sha256, curve25519-sha256@libssh.org, diffie-hellman-group16-sha512`) reprend exactement `05-helios-crypto.conf` : la surcharge est active.
- Test 3 : c'est `AllowGroups` qui refuse `root` avant même `PermitRootLogin`.
- Le serveur journalise aussi `srclimit_penalise … deferred penalty of 1 seconds` : `sshd` pénalise brièvement la source qui enchaîne des connexions sans s'authentifier.

Paramètres effectifs (`sshd -T`, `captures/sshd-T-final.txt`) :

```
port 2242 · maxauthtries 3 · permitrootlogin no · passwordauthentication no · loglevel VERBOSE · allowgroups ssh-admins
```

---

## Mission 3 — Surveillance des journaux et détection

### 3.1 journald persistant et dimensionné

`configs/50-helios.conf` :

| Directive | Rôle |
|---|---|
| `Storage=persistent` | Journaux conservés dans `/var/log/journal`, donc après redémarrage |
| `Compress=yes` | Compression |
| `SystemMaxUse=500M`, `SystemKeepFree=1G`, `SystemMaxFileSize=50M` | Plafond d'espace utilisé, espace disque à toujours laisser libre, taille maximale d'un fichier |
| `MaxRetentionSec=1month`, `MaxFileSec=1day` | Rétention d'un mois, rotation journalière |
| `RateLimitIntervalSec=30s`, `RateLimitBurst=10000` | Limitation de débit par service (10 000 messages par 30 s) |
| `ForwardToSyslog=no` | Pas de double transmission vers syslog |
| `Seal=yes` | Scellement des journaux (effectif une fois la clé générée par `journalctl --setup-keys`) |

```
$ journalctl --disk-usage
Archived and active journals take up 8.0M in the file system.
$ ls -ld /var/log/journal/f5b60f40…
drwxr-sr-x+ 2 root systemd-journal 4096  4 nov. 12:58 /var/log/journal/f5b60f4081014460864fdc522418b393
$ journalctl --verify
PASS: …/user-1000.journal   PASS: …/user-5100.journal   PASS: …/user-1000@…journal
```

Après redémarrage, `journalctl --list-boots` liste plusieurs démarrages (`captures/list-boots.txt`) :

```
IDX BOOT ID                          FIRST ENTRY                  LAST ENTRY
 -1 845e5c72a16b47be8d6aadf5adbda85d Mon 2026-11-02 14:43:37 CET  Mon 2026-11-02 19:21:01 CET
  0 75c74afdc967436399aa589ff1edb9e3 Wed 2026-11-04 12:52:14 CET  Wed 2026-11-04 12:53:41 CET
```

Les critères sont atteints : trois démarrages sont listés après les redémarrages ultérieurs (le contrôle final compte 4 lignes, en-tête comprise) ✔.

### 3.2 Requêtes d'investigation

`captures/investigation.txt`. Cinq requêtes et ce qu'elles révèlent :

| # | Requête | Ce qu'elle révèle |
|---|---|---|
| 1 | `journalctl -u sshd.service --since '-2h' -p warning` | **`sshd` n'a pas démarré au boot** du 04/11 à 12:52:24 : `Bind to port 2242 on 10.42.0.10 failed: Cannot assign requested address`, idem sur `192.168.56.10`, puis `fatal: Cannot bind any address` et `Failed to start OpenSSH server daemon`. Cause : `sshd` démarre avant que les adresses de `ListenAddress` existent, car `NetworkManager-wait-online` est masqué depuis le TP1 (`network-online.target` n'attend donc plus le réseau). La première connexion ne date que de 12:53:24, soit environ une minute d'indisponibilité. Corrigé ensuite : `sshd` démarre désormais sans délai (vérifié après un nouveau redémarrage). |
| 2 | `journalctl _SYSTEMD_UNIT=sshd.service -g 'Invalid user\|Failed\|Accepted'` | Les connexions réussies, par clé ED25519, depuis `192.168.56.11` (tests de la mission 2) puis depuis `192.168.56.1` (poste d'administration). On y voit aussi, **à chaque connexion du poste d'administration**, une ligne `Failed publickey … RSA` suivie de `Accepted … ED25519` : l'agent propose d'abord une autre clé, refusée. Ces « échecs » ne sont pas une attaque ; ils justifient la **liste blanche** du script de la Mission 3.4. |
| 3 | `journalctl --facility=authpriv --since today` | Le cycle complet d'une session : `Accepted publickey` → `pam_unix(sshd:session): session opened` → `Starting session: shell on pts/1` → `Received disconnect … disconnected by user` → `session closed`, puis `sudo : TTY=pts/1 ; USER=root ; COMMAND=/bin/bash` (passage root par `sudo -i`). Chaque action est rattachée à un compte et une source. |
| 4 | `journalctl -t sudo -o json-pretty` | La forme structurée d'un événement sudo : `_AUDIT_LOGINUID=1000` (compte d'origine), `_UID`, `_CMDLINE=sudo -i`, `_EXE=/usr/bin/sudo`, `_SYSTEMD_SESSION`, `_SELINUX_CONTEXT`, `_BOOT_ID`, avec `MESSAGE` `sysops : TTY=tty1 ; USER=root ; COMMAND=/bin/bash`. Ces champs permettent des requêtes précises (par utilisateur, par session, par démarrage). |
| 5 | `journalctl -b -1 -p err` (démarrage précédent) | Une chronologie de la machine : avertissements VirtualBox (`Unmaintained driver … e1000`, `vmwgfx … unsupported hypervisor`), `dnf makecache` en échec, **`Watchdog timeout` de `systemd-journald` et `systemd-udevd` avec core dumps** (02/11 16:24 et 18:02) et un *soft lockup* du CPU (17:38) : la VM a été figée, ce qui explique vraisemblablement les décalages d'horloge entre les deux VM. Y figurent aussi les traces du TP2 : `julien : command not allowed … restart sshd` et `status … --no-pager` (la règle sudo exacte refuse l'argument supplémentaire), `nadia : command not allowed … list`, `julien : 1 incorrect password attempt`, et `firewalld : NAME_CONFLICT new_ipset 'helios-blacklist'` (ipset déjà existant, sans conséquence). |

Compléments :
- `lastb` : 6 échecs de `nadia` à 15:40, ceux du test de verrouillage du TP2.
- `last -F` : sessions de `sysops` depuis `192.168.56.1`, et la ligne `reboot system boot` du 04/11 12:52.
- `lslogins` : `FAILED-LOGIN` de `nadia` (02/11 15:40) ; `root` et `sysops` n'ont **pas de date de changement de mot de passe** (`1969-déc.31`, champ vide) contrairement aux comptes créés au TP2 : à signaler pour l'hygiène des comptes.
- `journalctl _UID=5101 --since today` : aucune entrée, `nadia` n'ayant rien fait depuis le dernier démarrage.

### 3.3 auditd

`configs/90-helios.rules`, chargé par `augenrules --load` (`captures/auditctl-l.txt`) : **12 règles** ✔ (critère : au moins 10).

| Règle | Clé | Surveille |
|---|---|---|
| `-w /etc/passwd /etc/shadow /etc/group /etc/gshadow -p wa` | `identity` | Écriture et changement d'attributs des fichiers d'identité |
| `-w /etc/sudoers /etc/sudoers.d -p wa` | `sudoers` | La délégation sudo |
| `-w /etc/ssh/sshd_config /etc/ssh/sshd_config.d -p wa` | `sshd-config` | La configuration SSH |
| `-w /usr/local/bin/helios-lastlog -p x` | `helios-setgid` | Chaque exécution du binaire setgid du TP2 |
| `-a always,exit -F arch=b64/b32 -S execve -F euid=0 -F auid>=1000 -F auid!=unset` | `privesc` | Toute commande exécutée en root par un compte humain (`auid` conservé au travers de `sudo`/`su`) |
| `-w /etc/firewalld -p wa` | `firewall` | La configuration du pare-feu |

(`auditctl -l` affiche `auid!=-1`, forme normalisée de `auid!=unset`.)

**Preuves** (`captures/ausearch.txt`) :

- `ausearch -k sudoers -i` : création puis suppression de `/etc/sudoers.d/test-audit` par `touch` (`syscall=openat`) et `rm` (`unlinkat`), avec `auid=sysops` et `tty=pts2`, ainsi que les événements `CONFIG_CHANGE … op=add_rule` du chargement des règles ✔.
- `ausearch -k helios-setgid -i` : exécution de `/usr/local/bin/helios-lastlog` par `julien` :

```
type=SYSCALL … syscall=execve success=yes … auid=sysops uid=julien gid=transport euid=julien egid=telemetry sgid=telemetry … exe=/usr/local/bin/helios-lastlog key=helios-setgid
```

  On voit le bit setgid à l'œuvre (`egid=telemetry`, `uid` inchangé) ; `auid=sysops` indique que la session `su - julien` a été ouverte depuis `sysops`.
- `ausearch -k privesc -i --start today` : commandes lancées depuis le shell root :

```
type=EXECVE … a0=tail a1=-20
type=SYSCALL … syscall=execve success=yes … auid=sysops uid=root euid=root tty=pts2 comm=tail exe=/usr/bin/tail key=privesc
```

  Même derrière un shell `root`, `auid=sysops` identifie l'humain, ce qui est l'objectif de cette règle.
- `ausearch -m USER_LOGIN,USER_AUTH -i` : `op=pubkey … res=failed` (proposition de la première clé) puis `op=pubkey_auth grantors=auth-key … res=success` et `USER_LOGIN … id=sysops … addr=192.168.56.1 … res=success` ; `op=PAM:authentication grantors=pam_faillock,pam_unix … exe=/usr/bin/sudo res=success` pour les sudo de `sysops` et `julien`.

**Rapports** (`captures/aureport.txt`) :

```
Authentication Summary     :  86 sysops · 35 nadia · 30 julien · 6 tarek · 6 audit-ext
Failed Summary             :  18 failed logins · 47 failed authentications · 2 changes to accounts/groups · 113 events
Key Summary                :  33 privesc · 4 identity · 4 sudoers · 2 sshd-config · 2 helios-setgid · 1 firewall
```

Les clés `identity`, `sudoers`, `sshd-config` et `firewall` comptent surtout les événements de chargement des règles ; `privesc` domine (33) car chaque commande root d'un compte humain est enregistrée, y compris les commandes d'investigation elles-mêmes.

### 3.4 Automatiser la détection (`helios-watch-auth.sh`)

Script (`configs/helios-watch-auth.sh`) qui compte les échecs SSH par adresse source sur une fenêtre glissante de 10 minutes et ajoute à l'`ipset` `helios-blacklist` toute adresse **dépassant 5 échecs**.

| Contrainte | Mise en œuvre |
|---|---|
| Mode strict | `set -euo pipefail`, `IFS=$'\n\t'`, constantes en `readonly` |
| Verrou | `exec 9>"$LOCK"` + `flock -n 9` (rc=2 si une instance tourne déjà) |
| Nettoyage / journalisation | `trap cleanup EXIT`, `trap … INT TERM`, `logger -t helios-watch-auth` vers journald |
| Prérequis | rc=3 si `firewall-cmd` est absent ou `firewalld` inactif |
| Comptage | `journalctl -u sshd.service --since -10min -o cat`, extraction de l'adresse source (`Invalid user … from IP` et `Failed <méthode> for <compte> from IP`), `sort \| uniq -c`, filtre `> 5` |
| Liste blanche | `WHITELIST=(192.168.56.1)` : le poste du formateur n'est jamais bloqué |
| Idempotence | L'état est tenu dans `/var/lib/helios/blocked.txt` : une adresse déjà présente ne génère pas de seconde alerte |
| Persistance | À chaque passage, les adresses de l'état absentes de l'`ipset` sont réappliquées (les entrées ajoutées à chaud disparaissent au `--reload` ou au redémarrage) |
| Codes retour | 0 nominal, 2 verrou pris |

`helios-watch-auth.service` : `Type=oneshot`, `After=firewalld.service sshd.service`, `Nice=10`, `IOSchedulingClass=idle`.
`helios-watch-auth.timer` : `OnCalendar=*:0/2` (toutes les 2 minutes), `Persistent=no`, `AccuracySec=10s`.

**Attaque simulée** : 8 tentatives SSH espacées de 10 s depuis srv-edge avec un utilisateur inexistant (`pirate`). L'espacement est nécessaire : la limite de débit du pare-feu (rafale de 5, puis 6/min) ne laisserait sinon passer que 5 connexions, soit un nombre qui ne **dépasse** pas le seuil.

```
nov. 04 13:02:01 helios-watch-auth[2992]: fin d execution rc=0
nov. 04 13:02:07 helios-watch-auth[3012]: fin d execution rc=0
nov. 04 13:04:01 helios-watch-auth[3134]: BLOQUE 192.168.56.11 : 8 echecs d authentification SSH sur 10min
nov. 04 13:04:01 helios-watch-auth[3135]: fin d execution rc=0
nov. 04 13:04:16 helios-watch-auth[3165]: fin d execution rc=0      ← passage suivant : aucune seconde alerte
$ firewall-cmd --ipset=helios-blacklist --get-entries
192.168.56.11
```

Le blocage de `192.168.56.11` est prouvé ✔, et le passage suivant, sans nouvelle alerte, démontre l'idempotence. Déblocage : arrêt du timer (sinon il rebloquerait la source tant que les échecs sont dans la fenêtre), puis `--remove-entry=192.168.56.11`, retrait de l'adresse de `blocked.txt`, et relance différée du timer par `systemd-run --on-active=11min`.

État final du timer :

```
NEXT                        LEFT     LAST                        PASSED  UNIT
Wed 2026-11-04 13:38:00 CET 56s left Wed 2026-11-04 13:36:06 CET 57s ago helios-watch-auth.timer
```

---

## Mission bonus — Immuabilité d'auditd et revue cryptographique

### Immuabilité (`-e 2`)

```
$ echo '-e 2' >> /etc/audit/rules.d/90-helios.rules ; augenrules --load
   (9 avertissements « Old style watch rules are slower » : les règles -w sont fonctionnelles mais moins performantes que -a always,exit -F path=…)
$ auditctl -s | grep enabled
enabled 2
$ auditctl -D ; echo "rc=$?"
Error deleting rule (Operation not permitted)
rc=255
```

Avec `-e 2`, les règles deviennent **immuables** : même root ne peut plus les supprimer ni les modifier (`auditctl -D` échoue). Seul un redémarrage lève ce verrouillage : la ligne `-e 2` a été retirée du fichier puis la machine a redémarré (retour à `-e 1`). L'intérêt est qu'un attaquant ayant obtenu root ne peut pas désactiver l'audit sans redémarrer, ce qui est lui-même visible.

### Rapports de la semaine

`aureport --start this-week --summary -i` : 4061 événements, 300 changements de configuration, 37 connexions, 26 connexions échouées, 120 authentifications dont 48 échouées, 531 événements cryptographiques, 6 clés. L'étendue annoncée commence en 1970 : certains événements d'amorçage ont été horodatés avant que l'horloge soit réglée.

`aureport --executable --summary -i` (extrait) :

```
1073 /usr/libexec/openssh/sshd-session      340 /usr/bin/su            232 /usr/bin/sudo
 598 /usr/lib/systemd/systemd               238 /usr/bin/python3.9     143 /usr/bin/python3.9 (deleted)
  81 /usr/sbin/auditctl                      17 /usr/bin/chage          15 /usr/sbin/useradd
```

`sshd-session` domine, ce qui correspond à l'activité SSH des trois jours. La mention `(deleted)` signale un exécutable remplacé sur le disque pendant qu'il tournait, probablement lors d'une mise à jour de paquets ; en production, ce point mérite une vérification.

### Comparaison avec l'état de l'art (`ssh -Q cipher`, `ssh -Q kex`)

Le client OpenSSH installé connaît une grande liste d'algorithmes, dont des algorithmes faibles ou obsolètes : `3des-cbc`, `aes*-cbc`, `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1`. Notre configuration n'en retient que trois pour le chiffrement, deux pour les MACs et trois pour l'échange de clés, tous modernes. Elle pourrait aller plus loin avec les échanges **hybrides post-quantiques** que cette version d'OpenSSH propose (`mlkem768x25519-sha256`, `sntrup761x25519-sha512`), qui protègent contre l'interception de trafic aujourd'hui pour un déchiffrement futur.

### `AuthenticationMethods publickey` contre `PasswordAuthentication no` seul

`PasswordAuthentication no` ne désactive qu'**une** méthode : d'autres restent possibles si elles sont activées (clavier-interactif, GSSAPI, hôte de confiance). `AuthenticationMethods publickey` exprime l'exigence inverse : **seule** la clé publique est acceptée, quelles que soient les autres directives, et la directive permet aussi de combiner des méthodes (par exemple `publickey,keyboard-interactive` pour une double authentification). C'est une liste blanche de méthodes plutôt qu'une liste noire, donc plus robuste face à une réactivation accidentelle d'une autre méthode.

---

## Vérification finale des critères de réussite

| Critère | Résultat |
|---|---|
| `firewall-cmd --get-default-zone` → `drop`, zones actives conformes | ✔ (`drop` : `enp0s3`, `enp0s9`, `enp0s10` ; `internal` : `bond0`, `bond0.42` ; `work` : `enp0s8`) |
| `nc -zv 192.168.56.10 22` échoue, `ssh -p 2242 sysops@…` réussit par clé | ✔ |
| `ssh -p 2242 root@…` et `nadia@…` refusés | ✔ |
| `sshd -T` : `passwordauthentication no`, `allowgroups ssh-admins` | ✔ |
| `semanage port -l \| grep ssh_port_t` contient 2242 | ✔ |
| `journalctl -k -g SSH-NEW` contient des lignes générées par les tests | ✔ |
| `journalctl --list-boots` : au moins deux démarrages | ✔ |
| `auditctl -l` : au moins 10 règles ; `ausearch -k sudoers -i` retourne un événement | ✔ (12 règles) |
| Après l'attaque simulée, l'`ipset` contient `192.168.56.11` | ✔ |
| `systemctl list-timers helios-watch-auth.timer` : prochaine exécution | ✔ |
