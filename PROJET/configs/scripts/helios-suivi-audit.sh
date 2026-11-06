#!/usr/bin/env bash
# helios-suivi-audit.sh - audit de conformite E1..E9 (lecture seule). rc 0 <=> 9/9.
set -o pipefail
export LC_ALL=C

WWW=/srv/helios/suivi/www
ARCH=/srv/helios/archives/suivi
FAILS=()

# t <description> <expression shell> : ajoute un echec si l'expression n'est pas vraie
# (commande absente ou fichier illisible => expression fausse => KO, jamais de faux OK)
t() { if ! eval "$2" >/dev/null 2>&1; then FAILS+=("$1"); fi; }
active() { [[ "$(systemctl is-active "$1" 2>/dev/null)" == "active" ]]; }
enabled() { [[ "$(systemctl is-enabled "$1" 2>/dev/null)" == "enabled" ]]; }
prop() { systemctl show -p "$2" --value "$1" 2>/dev/null; }

NOK=0; RC=1
report() {  # report <Ex> <libelle>
    if ((${#FAILS[@]}==0)); then echo "[OK] $1 - $2"; ((NOK++))
    else echo "[KO] $1 - $2 : $(IFS=';'; echo "${FAILS[*]}")"; fi
    FAILS=()
}

if [[ $EUID -ne 0 ]]; then echo "[KO] audit : a lancer en root" >&2; echo "Bilan : 0/9"; exit 3; fi

# ---------- E1
SH="$(getent shadow lea 2>/dev/null)"
t "groupe suivi gid 5003" '[[ "$(getent group suivi | cut -d: -f3)" == 5003 ]]'
t "lea uid 5104 gid 5003" '[[ "$(getent passwd lea | cut -d: -f3,4)" == "5104:5003" ]]'
t "commentaire de lea" '[[ "$(getent passwd lea | cut -d: -f5)" == "Lea Fabre - responsable suivi des tournees" ]]'
t "vieillissement lea 1/90/14/7" '[[ "$(echo "$SH" | cut -d: -f4,5,6,7)" == "1:90:14:7" ]]'
t "lea hors wheel/ssh-admins" '! id -nG lea | tr " " "\n" | grep -xE "wheel|ssh-admins"'
t "helios-suivi compte systeme" '[[ "$(id -u helios-suivi)" -lt 1000 ]]'
t "helios-suivi sans shell" 'getent passwd helios-suivi | cut -d: -f7 | grep -E "(nologin|/bin/false)$"'
t "home de helios-suivi" '[[ "$(getent passwd helios-suivi | cut -d: -f6)" == /srv/helios/suivi ]]'
t "pas de /home/helios-suivi" '[[ ! -e /home/helios-suivi ]]'
report E1 "comptes et groupe"

# ---------- E2
ACL="$(getfacl -p "$WWW" 2>/dev/null)"
t "www root:suivi 2770" '[[ "$(stat -c %U:%G:%a "$WWW")" == "root:suivi:2770" ]]'
t "ACL helios-suivi rwx" 'grep -x "user:helios-suivi:rwx" <<<"$ACL"'
t "ACL zabbix --x" 'grep -x "user:zabbix:--x" <<<"$ACL"'
t "masque rwx" 'grep -x "mask::rwx" <<<"$ACL"'
t "ACL par defaut" 'grep -x "default:other::---" <<<"$ACL" && grep -x "default:group::rwx" <<<"$ACL" && grep -x "default:user:helios-suivi:rwx" <<<"$ACL" && grep -x "default:mask::rwx" <<<"$ACL"'
t "helios-suivi ecrit dans www" 'runuser -u helios-suivi -- test -w "$WWW"'
t "zabbix stat etat.json" 'runuser -u zabbix -- stat "$WWW/etat.json"'
t "zabbix ne liste pas www" '! runuser -u zabbix -- ls "$WWW"'
t "index.html present" '[[ -s "$WWW/index.html" ]]'
t "index.html groupe suivi" '[[ "$(stat -c %G "$WWW/index.html")" == suivi ]]'
report E2 "repertoire publie (setgid + ACL)"

# ---------- E3
P=/usr/local/sbin/helios-suivi-publish.sh
t "script executable" '[[ -x $P ]]'
t "syntaxe bash" 'bash -n $P'
t "set -euo pipefail" 'grep "^set -euo pipefail" $P'
t "flock" 'grep "flock -n" $P'
t "trap" 'grep "^trap " $P'
t "tag journald" 'grep "helios-suivi-publish" $P'
t "etat.json JSON valide" 'python3 -m json.tool "$WWW/etat.json"'
t "champs obligatoires" 'python3 -c "import json,sys; d=json.load(open(sys.argv[1])); [d[k] for k in (\"genere\",\"hote\",\"derniere_mesure\",\"charge_1min\",\"mem_dispo_ko\",\"mesures\")]" "$WWW/etat.json"'
t "journal de publication" 'journalctl -t helios-suivi-publish -n 1 --no-pager -q | grep .'
report E3 "script de publication"

# ---------- E4
S=helios-suivi.service
t "portail actif" 'active $S'
t "portail enabled" 'enabled $S'
t "User=helios-suivi" '[[ "$(prop $S User)" == helios-suivi ]]'
t "MemoryMax 128M" '[[ "$(prop $S MemoryMax)" == 134217728 ]]'
t "CPUQuota 50%" '[[ "$(prop $S CPUQuotaPerSecUSec)" == 500ms ]]'
t "Restart=on-failure" '[[ "$(prop $S Restart)" == on-failure ]]'
t "rattache a helios.target" 'systemctl list-dependencies helios.target 2>/dev/null | grep helios-suivi.service'
t "score <= 4.0" 'systemd-analyze security $S --no-pager | grep -E "Overall exposure level" | grep -oE "[0-9]+\.[0-9]+" | awk "{exit !(\$1<=4.0)}"'
t "GET / = 200" '[[ "$(curl -s -o /dev/null --max-time 5 -w %{http_code} http://127.0.0.1:8080/)" == 200 ]]'
t "GET /etat.json = 200" '[[ "$(curl -s -o /dev/null --max-time 5 -w %{http_code} http://127.0.0.1:8080/etat.json)" == 200 ]]'
t "publish oneshot/helios-suivi" '[[ "$(prop helios-suivi-publish.service Type)" == oneshot && "$(prop helios-suivi-publish.service User)" == helios-suivi ]]'
t "publish n ecrit que dans www" '[[ "$(prop helios-suivi-publish.service ProtectSystem)" == strict && "$(prop helios-suivi-publish.service ReadWritePaths)" == "$WWW" ]]'
t "publish.timer actif+enabled" 'active helios-suivi-publish.timer && enabled helios-suivi-publish.timer'
t "timer 2 min" 'systemctl cat helios-suivi-publish.timer | grep -E "^OnUnitActiveSec=2min$"'
t "etat.json recent (<300 s)" '(( $(date +%s) - $(stat -c %Y "$WWW/etat.json") < 300 ))'
report E4 "units systemd"

# ---------- E5
F=/etc/sudoers.d/92-helios-suivi
t "visudo -c" 'visudo -cf $F'
t "0440 root:root" '[[ "$(stat -c %a:%U:%G $F)" == 0440:root:root || "$(stat -c %a:%U:%G $F)" == 440:root:root ]]'
t "pas de NOPASSWD" '! grep NOPASSWD $F'
t "pas de joker" '! grep -v "^#" $F | grep "\*"'
for c in "/usr/bin/systemctl restart helios-suivi.service" "/usr/bin/systemctl status --no-pager helios-suivi.service" \
         "/usr/bin/systemctl start helios-suivi-publish.service" "/usr/bin/journalctl -u helios-suivi.service -n 100 --no-pager" \
         "/usr/bin/journalctl -u helios-suivi-publish.service -n 100 --no-pager"; do
    t "autorise: $c" "sudo -l -U lea $c"
done
for c in "/usr/bin/systemctl restart sshd" "/usr/bin/systemctl restart sshd.service" "/usr/bin/systemctl stop helios-suivi.service" \
         "/usr/bin/journalctl -u helios-suivi.service -n 100 --no-pager --vacuum-size=1M" "/usr/bin/journalctl --vacuum-size=1M" \
         "/usr/bin/systemctl restart helios-suivi.service --force" "/bin/bash"; do
    t "refuse: $c" "! sudo -l -U lea $c"
done
report E5 "delegation sudo"

# ---------- E6
t "8080 internal runtime" '[[ "$(firewall-cmd --zone=internal --query-port=8080/tcp)" == yes ]]'
t "8080 internal permanent" '[[ "$(firewall-cmd --permanent --zone=internal --query-port=8080/tcp)" == yes ]]'
ZONES="$(firewall-cmd --get-zones 2>/dev/null)"
t "liste des zones lisible" '[[ -n "$ZONES" ]]'
for z in $ZONES; do
    [[ $z == internal ]] && continue
    t "8080 absent de $z" "! firewall-cmd --zone=$z --list-ports | grep -E '(^| )8080/' && ! firewall-cmd --zone=$z --list-rich-rules | grep 8080 && ! firewall-cmd --permanent --zone=$z --list-ports | grep -E '(^| )8080/' && ! firewall-cmd --permanent --zone=$z --list-rich-rules | grep 8080"
done
t "rich rules internal sans 8080" '! firewall-cmd --zone=internal --list-rich-rules | grep 8080'
t "zone par defaut drop" '[[ "$(firewall-cmd --get-default-zone)" == drop ]]'
t "firewalld actif" 'active firewalld.service'
t "regle nft 8080" 'nft list ruleset | grep 8080'
report E6 "pare-feu"

# ---------- E7
SSHD="$(sshd -T 2>/dev/null)"
t "port 2242" 'grep -x "port 2242" <<<"$SSHD"'
t "permitrootlogin no" 'grep -x "permitrootlogin no" <<<"$SSHD"'
t "passwordauthentication no" 'grep -x "passwordauthentication no" <<<"$SSHD"'
t "allowgroups ssh-admins" 'grep -x "allowgroups ssh-admins" <<<"$SSHD"'
t "lea hors ssh-admins" '! id -nG lea | tr " " "\n" | grep -x ssh-admins'
t "watch-auth.timer actif" 'active helios-watch-auth.timer'
t "journald persistant" '[[ -d /var/log/journal ]] && grep -rhqE "^Storage=persistent" /etc/systemd/journald.conf /etc/systemd/journald.conf.d/'
t "SELinux enforcing" '[[ "$(getenforce)" == Enforcing ]]'
report E7 "non-regression securite"

# ---------- E8
t "zabbix-agent2 actif+enabled" 'active zabbix-agent2.service && enabled zabbix-agent2.service'
t "sysstat-collect.timer actif+enabled" 'active sysstat-collect.timer && enabled sysstat-collect.timer'
t "Server=127.0.0.1" 'grep -E "^Server=127.0.0.1$" /etc/zabbix/zabbix_agent2.conf'
t "helios.suivi.http = 200" '[[ "$(zabbix_get -s 127.0.0.1 -k helios.suivi.http)" == 200 ]]'
t "helios.suivi.age < 300" 'a=$(zabbix_get -s 127.0.0.1 -k helios.suivi.age); [[ "$a" =~ ^[0-9]+$ ]] && (( a < 300 ))'
report E8 "supervision Zabbix/sysstat"

# ---------- E9
LAST="$(find "$ARCH" -maxdepth 1 -name 'suivi-????????-??????.tar.gz' -printf '%f\n' 2>/dev/null | sort | tail -n 1)"
t "archive presente" '[[ -n "$LAST" ]]'
t "empreinte valide" '[[ -n "$LAST" ]] && (cd "$ARCH" && sha256sum -c --quiet "$LAST.sha256")'
t "archives <= 7" '(( $(find "$ARCH" -maxdepth 1 -name "suivi-*.tar.gz" | wc -l) <= 7 ))'
t "archives dir helios:helios 750" '[[ "$(stat -c %U:%G:%a /srv/helios/archives)" == helios:helios:750 ]]'
LIST="$(tar -tzf "$ARCH/$LAST" 2>/dev/null)"
for m in srv/helios/suivi/www/ etc/sudoers.d/92-helios-suivi etc/zabbix/zabbix_agent2.d/helios-suivi.conf \
         usr/local/sbin/helios-suivi-publish.sh usr/local/sbin/helios-suivi-backup.sh \
         etc/systemd/system/helios-suivi.service etc/systemd/system/helios-suivi-publish.service \
         etc/systemd/system/helios-suivi-publish.timer etc/systemd/system/helios-suivi-backup.service \
         etc/systemd/system/helios-suivi-backup.timer; do
    t "archive sans $m" "grep -x '$m' <<<\"\$LIST\""
done
t "backup.timer actif+enabled" 'active helios-suivi-backup.timer && enabled helios-suivi-backup.timer'
t "timer 03:15 Persistent" 'systemctl cat helios-suivi-backup.timer | grep "OnCalendar=\*-\*-\* 03:15:00" && systemctl cat helios-suivi-backup.timer | grep "Persistent=true"'
report E9 "sauvegarde"

echo "Bilan : $NOK/9"
[[ $NOK -eq 9 ]]
