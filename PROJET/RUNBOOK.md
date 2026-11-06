# RUNBOOK — Portail de suivi des tournées (srv-core)

Service : `helios-suivi.service` (HTTP :8080, réseau métier) · publication : `helios-suivi-publish.timer` (2 min) · sauvegarde : `helios-suivi-backup.timer` (03:15).
Contrôle global (root) : `/usr/local/sbin/helios-suivi-audit.sh` → doit afficher `Bilan : 9/9`.

## 1. Le portail ne répond plus
- **Symptôme** : alerte Zabbix « helios.suivi.http ≠ 200 » (Haute) ou `curl` ≠ 200.
- **Diagnostic** : `systemctl status helios-suivi.service` · `journalctl -u helios-suivi.service -n 100 --no-pager` · `ss -tlnp | grep 8080`
- **Réparation** : `sudo systemctl restart helios-suivi.service` (si échec persistant : lire le journal, puis `ausearch -m AVC -ts recent` ; ne jamais passer SELinux en permissive).
- **Vérification** : `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/etat.json` → `200`

## 2. etat.json est figé
- **Symptôme** : alerte Zabbix « helios.suivi.age > 300 » (Moyenne) ou `genere` ancien dans le JSON.
- **Diagnostic** : `systemctl list-timers helios-suivi-publish.timer` · `journalctl -u helios-suivi-publish.service -n 100 --no-pager` · `systemctl is-active helios-collect.service` · `tail -n 2 /var/lib/helios/telemetry.csv`
- **Réparation** : relancer le collecteur si arrêté (admin : `systemctl start helios-collect.service`), puis `sudo systemctl start helios-suivi-publish.service` (code 2 = autre instance en cours, 3 = prérequis manquant, 1 = ligne de télémétrie invalide).
- **Vérification** : `zabbix_get -s 127.0.0.1 -k helios.suivi.age` → nombre < 300 (ou `curl http://127.0.0.1:8080/etat.json` : `genere` récent).

## 3. Injoignable depuis le réseau métier alors que le service tourne
- **Symptôme** : `curl` OK en local sur srv-core, KO depuis srv-edge (`10.42.0.10:8080`).
- **Diagnostic** : `firewall-cmd --zone=internal --query-port=8080/tcp` · `firewall-cmd --get-active-zones` · `ip -br a show bond0` · `ss -tlnp | grep 8080`
- **Réparation** : (admin) `firewall-cmd --zone=internal --add-port=8080/tcp --permanent && firewall-cmd --reload` — jamais dans une autre zone, jamais firewalld arrêté.
- **Vérification** : depuis srv-edge `curl -s -o /dev/null -w '%{http_code}\n' http://10.42.0.10:8080/etat.json` → `200` ; `nc -zv -w2 192.168.56.10 8080` doit rester en échec.

## 4. Restaurer le portail (suppression ou corruption)
- **Symptôme** : `index.html` ou `etat.json` absent/corrompu, 404 sur `/`.
- **Diagnostic** : `ls -l /srv/helios/suivi/www` · `cd /srv/helios/archives/suivi && ls -1t suivi-*.tar.gz | head -1 && sha256sum -c --quiet <archive>.sha256`
- **Réparation** (admin, un seul fichier) : `A=$(ls -1t /srv/helios/archives/suivi/suivi-*.tar.gz | head -1); tar -xzpf "$A" --acls --xattrs --selinux -C / srv/helios/suivi/www/index.html` ; pour tout le répertoire : même commande avec `srv/helios/suivi`. Puis `systemctl start helios-suivi-publish.service`.
- **Vérification** : `getfacl /srv/helios/suivi/www/index.html` (propriétaire:groupe suivi, ACL helios-suivi) et `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/` → `200`
