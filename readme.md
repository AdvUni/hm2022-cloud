---
layout: post
title:  "Advanced UniByte Hausmesse 2022 - Build your own cloud in 30 minutes
date:   2022-06-06
---

# Willkommen zum Vortrag "Build your own cloud in 30 minutes"!

Dieses Dokument ist als Begleitmaterial zu dem Hausmesse Vortrag bei der Advanced UniByte gedacht.

Es soll noch einmal genau die nötigen Schritte erklären die zum Aufbau einer eigenen NextCloud Installation auf einem kleinen PC oder RaspberryPi notwendig sind.

Dabei ist dieses Dokument als "lebendige Dokumentation" gedacht, das bedeutet wenn irgendwelche Schritte unklar sind, oder sich Fehler eingeschlichen haben, bitte nicht zögern ein Issue zu eröffnen. Auch Pull Requests sind gerne gesehen!

In diesem Sinne: Viel Spaß

## Voraussetzungen

Wir brauchen:
- Einen RaspberryPi oder (gerne auch älteren) PC/Laptop
- Ein relativ aktuelles Linux. Die Distribution ist dabei egal, wobei in diesem Dokument von einer Ubuntu-artigen Distribution ausgegangen wird. Die Kommandos zur Paket-Installation oder zum Dienste-Management müssen bei Bedarf auf die verwendete Distribution angepasst werden.
- Eine Internet-Verbindung
- Eine feste IP im LAN, am besten über Kabel (weil einfacher und meist bessere Verbindung)
- Eine DNS Domäne, z.B. von domaindiscount24.com o.ä.
- Ein Router im Heim-LAN, welcher Port-Forwarding beherrscht
- Eine (externe) Festplatte oder ausreichend großen USB Stick für die Daten

## Installation Linux

Die Installation von Linux selbst wird hier nicht weiter beschrieben. Üblicherweise genügt eine Standard-Installation, bzw. beim Raspberry Pi das Vorbereiten einer SD Karte mit dem RaspberryPi OS Image.

Eine feste IP Adresse kann man auf einem RaspberryPi über die Datei /etc/dhcpcd.conf setzen:

    pi@raspberrypi:~ $ sudo vi /etc/dhcpcd.conf
    ...
    # Example static IP configuration:
    interface eth0
    static ip_address=192.168.1.3/24
    static routers=192.168.1.1
    static domain_name_servers=192.168.1.2
    ...

Bei schwächeren Computern, wie z.B. auch dem Raspberry Pi, sollte man zusätzlich noch die grafische Oberfläche deaktivieren:

    pi@raspberrypi:~ $ sudo systemctl enable multi-user.target
    pi@raspberrypi:~ $ sudo systemctl set-default multi-user.target

Außerdem ist es für k8s empfehlenswert, Swapping zu deaktivieren. Zum einen da k8s selbst schon die verfügbaren RAM Ressourcenfür die einzelnen Pods verwaltet und limitiert, zumn Anderen um die Lebensdauer der SD Karte zu erhöhen und die I/O Last auf der evtl. langsamen Festplatte zu verringern:

    pi@raspberrypi:~ $ sudo dphys-swapfile swapoff
    pi@raspberrypi:~ $ sudo dphys-swapfile uninstall
    pi@raspberrypi:~ $ sudo update-rc.d dphys-swapfile remove
    pi@raspberrypi:~ $ sudo apt-get purge -y dphys-swapfile

Auf dem RaspberryPi OS fehlen außerdem standardmäßig ein paar wichtige Einstellungen, die k3s benötigt. Um diese zu aktivieren muss die Datei /boot/cmdline.txt editiert werden, und die Zeile dort folgendermaßen angepasst werden

    console=serial0,115200 ..... cgroup_memory=1 cgroup_enable=memory

Es müssen also am Ende die zwei Parameter `cgroup_memory=1 cgroup_enable=memory` hinzugefügt werden. Ob dies bei anderen Distributionen auch vonnöten ist kann später mit dem `k3s check-config` Tool überprüft werden.

Wenn für die NextCloud-Daten eine externe Festplatte oder ein USB Stick benutzt werden soll, so muss dieser evtl. formatiert und gemountet werden. Für unser Projekt werden wir den USB Stick mit dem ext4 Dateisystem formatieren und unter `/k8s-data` einhängen:

    sudo fdisk /dev/sda
    ...
    sudo mkfs.ext4 -L k8s-data /dev/sda1

Achtung: Unbedingt darauf achten dass das richtige Device partitioniert/formatiert wird. Im Zweifelsfall hilft `lsblk` weiter.

Da wir beim Formatieren ein Label vergeben haben (`-L k8s-data`) können wir den Mount folgendermaßen persistent machen:

    pi@raspberrypi:~ $ sudo vi /etc/fstab
    ...
    LABEL=k8s-data      /k8s-data         ext4    defaults      0    0
    ...
    pi@raspberrypi:~ $ sudo mount -a

Nun sollte die Disk gemountet sein, was ein `df` bestätigen wird.

Aufgrund eines Bugs in einigen älteren Versionen des `iptables` Tools sollte dies deinstalliert werden, sofern es nicht mindestens die Version 1.8.6 hat. k3s bringt sein eigenes iptables mit und nutzt dieses, wenn im System keines installiert ist

    pi@raspberrypi:~ $ iptables --version
    iptables v1.8.2 (nf_tables)
    pi@raspberrypi:~ $ sudo apt-get remove -y iptables nftables
    pi@raspberrypi:~ $ iptables --version
    bash: iptables: command not found

Als letzten Schritt machen wir einen Reboot um sicherzustellen dass anschließend das System wieder sauber hochkommt.

    pi@raspberrypi:~ $ sudo systemctl reboot

## Einrichten des Routers

Nun konfigurieren wir den Router, so dass Anfragen aus dem Internet auf port 80 (für HTTP) und 443 (für HTTPS) an unseren RaspberryPi weitergeleitet werden. Die Umleitung von Port 80 kann später auch wieder entfernt werden, zum Testen ist diese aber sehr hilfreich.

Wie die Konfiguration auf dem Router durchgeführt werden muss ist vom Router-Modell abhängig. Im Zweifelsfall hilft hier eine Internet-Suche oder die Dokumentation weiter. Bei einem SpeedPort Neo sieht das entsprechende Menü folgendermaßen aus:

![Port Forwarding](images/speedport_neo.png)

Zum Testen der Port-Weiterleitung nutzen wir einen einfachen Python Webserver in einem leeren Verzeichnis:

    pi@raspberrypi:~ $ curl -s icanhazip.com
    198.51.100.17
    pi@raspberrypi:~ $ mkdir /tmp/foo
    pi@raspberrypi:~ $ cd /tmp/foo
    pi@raspberrypi:/tmp/foo $ sudo python3 -m http.server 80
    Serving HTTP on :: port 80 (http://[::]:80/) ...

Nun sollten wir in einem Browser die Adresse `http://198.51.100.17` aufrufen können und ein leeres Verzeichnis angezeigt werden. Kommt hingegen ein Fehler oder ein Timeout, so stimmt noch etwas bei der Port-Weiterleitung nicht.

## DNS Konfigurieren

Auch hier ist es wieder stark vom Provider abhängig, wie das dynamische DNS konfiguriert wird. Üblicherweise gibt es eine GUI in der man einen Hostnamen einträgt (z.B. `cloud.au-lab.de`) und dann einen Haken setzt bei "Dynamic DNS" oder so. Der Provider sollte DNS Updates via HTTPS Anfragen unterstützen, ansonsten sind die nächsten Schritte entsprechend anzupassen.

![DynamicDNS](/images/dyndns.png)

Bei DomainDiscount24 sieht der URL zum Update der DNS Datenbank folgendermaßen aus:

    https://dynamicdns.key-systems.net/update.php?hostname=HOSTNAME&pasword=PW&ip=auto

Für `HOSTNAME` und `PW` müssen die entsprechenden Daten eingesetzt werden.

Um das DNS Update zu testen reicht ein einfacher curl Aufruf:

    pi@raspberrypi:~ curl -s https://dynamicdns.key-systems.net/update.php?hostname=cloud.au-lab.de&password=123secret456&ip=auto

Nun muss man ein paar Minuten warten, bis die DNS Updates weltweit verteilt wurden und dann sollte folgendes Kommando funktionieren:

    pi@raspberrypi:~ host cloud.au-lab.de
    cloud.au-lab.de has address 198.51.100.17

## k3s installieren

Die Installation von k3s ist denkbar einfach: auf der Homepage, https://k3s.io, ist ein Kommando aufgeführt welches man einfach in einer Shell ausführt. Dadurch wird ein Skript heruntergeladen und gestartet, welches automatisch die Distribution, CPU-Architektur und weitere Details erkennt, die passenden k3s-binaries herunterlädt und diese installiert:

    pi@raspberrypi: ~$ curl -sfL https://get.k3s.io | sudo bash -
    [INFO]  Finding release for channel stable
    [INFO]  Using v1.21.5+k3s2 as release
    [INFO]  Downloading hash https://github.com/k3s-io/k3s/releases/download/v1.21.5+k3s2/sha256sum-arm64.txt
    [INFO]  Downloading binary https://github.com/k3s-io/k3s/releases/download/v1.21.5+k3s2/k3s
    [INFO]  Verifying binary download
    [INFO]  Installing k3s to /usr/local/bin/k3s
    [INFO]  Skipping installation of SELinux RPM
    [INFO]  Creating /usr/local/bin/kubectl symlink to k3s
    [INFO]  Creating /usr/local/bin/crictl symlink to k3s
    [INFO]  Creating /usr/local/bin/ctr symlink to k3s
    [INFO]  Creating killall script /usr/local/bin/k3s-killall.sh
    [INFO]  Creating uninstall script /usr/local/bin/k3s-uninstall.sh
    [INFO]  env: Creating environment file /etc/systemd/system/k3s.service.env
    [INFO]  systemd: Creating service file /etc/systemd/system/k3s.service
    [INFO]  systemd: Enabling k3s unit
    Created symlink /etc/systemd/system/multi-user.target.wants/k3s.service → /etc/systemd/system/k3s.service.
    [INFO]  systemd: Starting k3s

Anschließend muss noch eine Anpassung durchgeführt werden, damit auch normale User das `kubectl` Tool ausführen können. Standardmäßig ist dies nur root erlaubt:

    pi@raspberrypi:~ $ echo "K3S_KUBECONFIG_MODE=0644" | sudo tee /etc/systemd/system/k3s.service.env
    K3S_KUBECONFIG_MODE=0644
    pi@raspberrypi:~ $ sudo systemctl restart k3s

Anschließend sollte sich der Cluster schon folgendermaßen melden:

    pi@raspberrypi:~ $ kubectl get nodes
    NAME            STATUS   ROLES                  AGE     VERSION
    raspberrypi     Ready    control-plane,master   6m51s   v1.21.5+k3s2

## Kubernetes Grundlagen

Folgende Begriffe tauchen in diesem Dokument immer wieder auf und werden hier kurz beschrieben:

- **Manifest:** Ein Manifest bezeichnet eine YAML Datei, welche ein oder mehrere k8s-Objekte beschreibt.
- **Namespace:** ein Namespace kapselt mehrere k8s Objekte, die logisch zusammengehören. Namespaces dienen auch der administrativen Trennung, indem man bestimmten Usern Recht auf unterschiedliche Namespaces geben kann.
- **Pod:** Ein Pod kapselt einen (oder mehrere) Container, und ist üblicherweise die kleinste Einheit eines Services mit denen sich ein k8s-Administrator beschäftigt.
- **Secret:** Secrets dienen der Trennung von Passwörtern oder API Keys, so dass diese nicht in den Beschreibungen der Pods oder Deployments selbst auftauchen. Dadurch ist zum einen eine sichere Trennung gewährleistet (ein Admin, der Pods starten und stoppen darf, benötigt nicht zwingend Berechtigungen auf den Secrets und kann somit Passwörter nicht auslesen), zum anderen können dadurch dieselben Manifest-Dateien für mehrere Umgebungen verwendet werden, ohne dass man diese extra anpassen muss.
- **Deployment:** Ein Deployment kümmert sich um Scale-Out eines bestimmten Microservices. Dazu nimmt es ein Pod-Template und erzeugt, je nach gewünschter Anzahl der Replikas, einen oder mehrere Pods und kümmert sich um deren Lifecycle. Das Deployment startet weitere Pods wenn existierende wegfallen, und entfernd Pods wenn die gewünschte Anzahl an Replicas im Cluster reduziert wird.
- **Service:** Services dienen als Einstiegspunkt beim Zugriff auf einen (in potenziell mehreren Pods verteilten) Microservice. Sie stellen einen festen Zugriffspunkt für Frontend-Services zur verfügung (über eine feste IP und/oder einen festen, cluster-internen DNS Namen) und kümmern sich um die Verteilung der Anfragen auf den jeweils besten Pod (Load-Balancing).
- **Ingress:** Ein Ingress macht einen Service außerhalb des Clusters verfügbar. Meistens geht es dabei um HTTP Dienste, bei welchen der Ingress eine ähnliche Funktion erfüllt wie ein klassischer Reverse-Proxy: Virtual Host Verwaltung, Path-Based Routing, etc.

Um mit dem k8s Cluster zu interagieren wird das Tool `kubectl` verwendet. Im Folgenden werden ein paar der häufigsten Verwendungszwecke erklärt.

    kubectl [ -n namespace] get { object }
    kubectl [ -n namespace] get { object } { identifier }
    kubectl [ -n namespace] get { object }/{ identifier }

Optional kann man noch das Ausgabeformat auswählen, indem man `-o yaml`, `-o json`  oder `-o wide` anhängt

Mit diesem Kommando werden sämtliche k8s-Objekte eines bestimmten Typs angezeigt. Beispielsweise kann man sich alle Pods im Namespace `cloud` anzeigen lassen:

    kubectl -n cloud get pods

Oder nur einen bestimmten Pod:

    kubectl -n cloud get pod mein-erster-pod
    kubectl -n cloud get pod/mein-erster-pod -o wide

Die Schreibweise mit dem Schrägstrich ist dabei die präferierte. Anstelle von `-n namespace` kann man auch `-A` oder `--all-namespaces` angeben, um die Ausgabe über sämtliche Namespaces zu erhalten. Die Parameter für den Namespace können (bzw. müssen) bei allen `kubectl` Aufrufen angegeben werden.

Eine etwas detailliertere Beschreibung der Objekte bekommtn man mittels

    kubectl describe pod/mein-erster-pod

Man kann k8s-Objekte auch über `kubectl` anlegen, bearbeiten und löschen, wobei das selten genutzt wird, da man üblicherweise über Manifest-Dateien (YAML-Dateien) mit dem Cluster interagiert (siehe weiter unten). Trotzdem sollen diese Kommandos hier kurz erwähnt werden:

    kubectl create { object } { identifier }
    kubectl delete { object }/{ identifier }
    kubectl edit { object }/{ identifier }

Wichtig, beim Löschen von Namespaces werden auch sämtliche Objekte innerhalb dieses Namespaces gelöscht!

## Cronjobs waren gestern

Zu Hause hat man meist eine dynamische IP, was bedeutet dass man eigentlich regelmäßig (z.B. jede Stunde) die IP Adresse, auf die die DNS Domäne zeigt, aktualisieren muss. Dazu hat man klassischerweise einen cronjob benutzt, den man in Linux über die Datei `/etc/crontab` (oder eine Variante davon) konfiguriert.

K8s unterstützt uns auch hierbei, so dass man nicht auf die Linux cron Konfiguration angewiesen ist. Dazu erzeugt man ein Objekt vom Typ `CronJob`:

    apiVersion: batch/v1
    kind: CronJob
    metadata:
      namespace: dyndns
      name: dyndns-job
    spec:
      schedule: "13 * * * *"
      jobTemplate:
        spec:
          template:
            spec:
              containers:
              - name: cron
                image: busybox
                imagePullPolicy: IfNotPresent
                env:
                  - name: SECRET_HOSTNAME
                    valueFrom:
                      secretKeyRef:
                        name: dyndns-secret
                        key: hostname
                  - name: SECRET_PASSWORD
                    valueFrom:
                      secretKeyRef:
                        name: dyndns-secret
                        key: password
                  - name: URL
                    value: "https://dynamicdns.key-systems.net/update.php"
                command:
                - /bin/sh
                - -c
                - wget -O - "${URL}?hostname=${SECRET_HOSTNAME}&password=${SECRET_PASSWORD}&ip=auto"
              restartPolicy: OnFailure

Wir geben dem CronJob eine Schedule im standard UNIX Crontab Format mit, hier `13 * * * *`, was so viel bedeutet wie "13 Minuten nach jeder vollen Stunde". Außerdem definieren wir ein Pod-Template, welches der CronJob hernimmt um das tatsächliche Kommando auszuführen. Dazu dient hier ein BusyBox Container, dessen Standard-Kommando (eine Shell) durch einen Aufruf von `wget` ersetzt wird. Die Parameter für den Aufruf bekommen wir als Umgebungsvariable aus dem dazugehörigen Secret, welches wir folgendermaßen konfigurieren:

    apiVersion: v1
    kind: Secret
    metadata:
      namespace: dyndns
      name: dyndns-secret
    stringData:
      hostname: cloud.au-lab.de
      password: 1secret234!

Via `kubectl apply` spielen wir die beiden Manifest-Dateien in den Cluster ein:

    pi@raspberrypi:~ $ kubectl apply -f dyndns.yaml
    namespace/dyndns created
    cronjob.batch/dyndns-job created
    pi@raspberrypi:~ $ kubectl apply -f dyndns-secret.yaml
    secret/dyndns-secret created

Um nun nicht warten zu müssen, bis der Job das nächste mal automatisch startet, kann man ihn einmalig von Hand ausführen. Wichtig ist hier die Unterscheidung zwischen dem *CronJob*, welcher die Schedule definiert und den auszuführenden Pod, und dem *Job*, welcher einer aisgeführten Instanz eines Pods entspricht. Wir erzeugen also einen manuellen Job aus dem CronJob:

    pi@raspberrypi:~ $ kubectl -n dyndns create job --from=cronjob/dyndns-job testjob1
    job.batch/testjob1 created

Um zu überprüfen ob der Job sauber ausgeführt wurde können wir ihn mit `kubectl describe` ansehen oder mit `kubectl logs` seine Ausgaben anschauen:

    pi@raspberrypi:~$ kubectl -n dyndns-updater describe job/testjob1
    Name:           testjob1
    Namespace:      dyndns
    Selector:       controller-uid=219fa210-0e7a-4f42-926b-ddf4a73edc9e
    Labels:         controller-uid=219fa210-0e7a-4f42-926b-ddf4a73edc9e
                    job-name=testjob1
    Annotations:    cronjob.kubernetes.io/instantiate: manual
    Parallelism:    1
    Completions:    1
    Start Time:     Fri, 12 Nov 2021 16:42:55 +0100
    Completed At:   Fri, 12 Nov 2021 16:42:59 +0100
    Duration:       4s
    Pods Statuses:  0 Running / 1 Succeeded / 0 Failed
    Pod Template:
      Labels:  controller-uid=219fa210-0e7a-4f42-926b-ddf4a73edc9e
               job-name=testjob1
      Containers:
       cron:
        Image:      busybox
        Port:       <none>
        Host Port:  <none>
        Command:
          /bin/sh
          -c
          wget -O - "${URL}?hostname=${SECRET_HOSTNAME}&password=${SECRET_PASSWORD}&ip=auto"
        Environment:
          SECRET_HOSTNAME:  <set to the key 'hostname' in secret 'dyndns-web-secret'>  Optional: false
          SECRET_PASSWORD:  <set to the key 'password' in secret 'dyndns-web-secret'>  Optional: false
          URL:              https://dynamicdns.key-systems.net/update.php
        Mounts:             <none>
      Volumes:              <none>
    Events:
      Type    Reason            Age   From            Message
      ----    ------            ----  ----            -------
      Normal  SuccessfulCreate  51s   job-controller  Created pod: testjob1-dplw5
      Normal  Completed         47s   job-controller  Job completed

    pi@raspberrypi:~$ kubectl -n dyndns logs job/testjob1
    wget: note: TLS certificate validation not implemented
    [RESPONSE]
    code = 200
    description = Command completed successfully
    queuetime = 0
    runtime = 0.099
    EOF

Im Output sehen wir die Rückmeldung des API Servers unseres DNS Providers, das IP Update lief also problemlos durch.

Der Cronjob bewahrt außerdem die letzten 3 Jobs auf bevor deren Pods gelöscht werden, so dass man auch noch von älteren Jobs die Logs ansehen kann. Diese sieht man mit `kubectl get job`:

    pi@raspberrypi:~ $ kubectl get job -n dyndns
    NAME                            COMPLETIONS   DURATION   AGE
    job.batch/testjob1              1/1           4s         90m
    job.batch/dyndns-job-27278931   1/1           1s         60s
    job.batch/dyndns-job-27278893   1/1           1s         41s


