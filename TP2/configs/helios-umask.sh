# umask 002 pour les membres de transport (travail collaboratif setgid), 027 sinon.
if id -nG | tr ' ' '\n' | grep -qx transport ; then umask 002 ; else umask 027 ; fi
