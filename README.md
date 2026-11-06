# Administration d'un Linux Server

Dépôt regroupant les travaux pratiques du module **Administration d'un Linux Server** (BTC2).

| | |
|---|---|
| **Module** | Administration d'un Linux Server |
| **Niveau** | BTC2 |
| **Auteur** | Imad Atouani |
| **Formateur** | Ayoub Benhamdi |

## Organisation du dépôt

```
adminsyslinux/
├── README.md
├── TP1/
│   ├── RAPPORT.md      rapport complet
│   ├── configs/        units, drop-in, script, timer, configuration du bond
│   └── captures/       graphes de boot, bascule du bond, capture VLAN, routage
├── TP2/
│   ├── RAPPORT.md      rapport complet
│   ├── configs/        politique de mots de passe, faillock, umask, sudoers, helios-lastlog, sauvegarde des ACL
│   └── captures/       setgid et sticky, umask, ACL et masque, sudo, évasion de shell
├── TP3/
│   ├── RAPPORT.md      rapport complet
│   ├── configs/        zones firewalld, drop-ins SSH, journald, règles auditd, script et timer de détection
│   └── captures/       nmap, tests SSH, règles nftables, journaux, audit, blocage de l'attaque simulée
└── PROJET/
    ├── RAPPORT.md      tableau de conformité, justifications, restauration, mesure sous charge, limites
    ├── RUNBOOK.md      fiche d'astreinte du portail de suivi
    ├── configs/        units, scripts (publication, sauvegarde, audit), sudoers, sonde Zabbix, ACL, pare-feu
    └── preuves/        audit.txt, score de durcissement, mesure sar, SELinux, captures Zabbix
```
