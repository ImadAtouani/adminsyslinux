/* helios-lastlog : affiche la fin du journal applicatif Helios.
 * Installe setgid telemetry : l'egid permet la lecture, l'uid reste l'appelant.
 * Environnement et chemin figes pour eviter toute injection via PATH/IFS. */
#include <unistd.h>
#include <stdio.h>

int main(void)
{
    char *env[] = { "PATH=/usr/bin:/bin", "IFS= \t\n", NULL };
    execle("/usr/bin/tail", "tail", "-n", "10",
           "/var/log/helios/app.log", (char *)NULL, env);
    perror("execle");
    return 1;
}
