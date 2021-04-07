# Grok Patterns (Linux, Windows, Fortinet Fortigate)
The Grok Patterns I wrote to parse Linux, Fortigate and Windows logs during my internship @ ICTeam

You may need to tweak and change them a little to serve your purpose, but since I've noticed there are not many examples of working Grok Patterns on the internet, I hope these can be useful to someone.

I applied the following patterns to the logs in order to extract specific data and then use the values to create widgets in the "Dashboard" section of Graylog. My goal was in fact to create reports that could be easily interpreted by clients.

## Grok patterns for SU:

If someone tries to become SU and types the wrong password, this is how you can intercept him (su_to è l'account a cui hanno tentato l'accesso, fallendo. utente_fallito_su è l'utente che ha tentato di farlo):

```%{MONTH:mese}%{SPACE}%{BASE10NUM:giorno} %{TIME:ora}%{GREEDYDATA}graylog su: FAILED SU \(to %{GREEDYDATA:su_to}\)%{GREEDYDATA:utente_fallito_su}%{GREEDYDATA}on pts/0```
#
If you want to create a table with all the SU who connected:

```%{MONTH:mese}%{SPACE}%{BASE10NUM:giorno} %{TIME:ora} %{GREEDYDATA}graylog su: %{GREEDYDATA}pam_unix\(su-l:session\):%{GREEDYDATA:stato_sessione}%{SPACE} %{GREEDYDATA}for user root by%{SPACE}%{GREEDYDATA:utente_su}%{GREEDYDATA}\(uid=%{BASE10NUM}\)```
____

## Grok pattern for failed authentications:

Normal user fails authentication, pattern for logs without user name:

```%{MONTH:mese}%{SPACE}%{BASE10NUM:numbase10} %{TIME:ora}%{GREEDYDATA}graylog sshd\[%{BASE10NUM}\]%{GREEDYDATA}: (pam_sss|pam_unix)\(sshd:auth\):%{GREEDYDATA:autenticazione_fallita};%{GREEDYDATA}logname= uid=.* euid=.* tty=.* ruser=.* rhost=%{IP}```
#
Autenticazione fallita 2:

```%{MONTH:mese} %{BASE10NUM:numbase10} %{TIME:ora}%{GREEDYDATA}graylog sshd\[%{BASE10NUM}\]%{GREEDYDATA}: pam_unix\(sshd:auth\):%{GREEDYDATA:autenticazione_fallita}%{GREEDYDATA}logname= uid=0 euid=0 tty=ssh ruser= rhost=%{IP} %{GREEDYDATA:utente}user=```
#
Autenticazione fallita nagios|moruga|graylog, pam_unix|pam_sss SENZA UTENTE:

```%{MONTH:mese}%{SPACE}%{BASE10NUM:numbase10} %{TIME:ora}%{GREEDYDATA}(moruga|icteam-nagios.icteam.local|graylog) sshd\[%{BASE10NUM}\]%{GREEDYDATA}: (pam_sss|pam_unix)\(sshd:auth\):%{GREEDYDATA:autenticazione_fallita};%{GREEDYDATA}logname=.* uid=.* euid=.* tty=.* ruser=.* rhost=.*```
#
Autenticazione fallita pam_unix|pam_sss CON UTENTE:

```%{MONTH:mese}%{SPACE}%{BASE10NUM:giorno} %{TIME:ora} %{GREEDYDATA}graylog sshd\[%{BASE10NUM}\]: %{GREEDYDATA}(pam_unix|pam_sss)\(sshd:auth\): %{GREEDYDATA:autenticazione_fallita}%{GREEDYDATA}; logname=.* uid=.* euid=.* tty=.* ruser=.* rhost=.* user=%{GREEDYDATA:utente}```
____

[Lorenzo](https://www.linkedin.com/in/lorenzomagni97/)
