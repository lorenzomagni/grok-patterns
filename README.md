# Grok Patterns (Linux, Windows, Fortinet Fortigate)
The Grok Patterns I wrote to parse Linux, Fortigate and Windows logs during my internship @ ICTeam

You may need to tweak and change them a little to serve your purpose, but since I've noticed there are not many examples of working Grok Patterns on the internet, I hope these can be useful to someone.

I applied the following patterns to the logs in order to extract specific data and then use the values to create widgets in the "Dashboard" section of Graylog. My goal was in fact to create reports that could be easily interpreted by clients.

## Grok patterns for SU:

If someone tries to become SU and types the wrong password, this is how you can intercept him:

```%{MONTH:mese}%{SPACE}%{BASE10NUM:giorno} %{TIME:ora}%{GREEDYDATA}graylog su: FAILED SU \(to root\)%{GREEDYDATA:utente_fallito_su}%{GREEDYDATA}on pts/0```
_____

If you want to create a table with all the SU who connected:

```%{MONTH:mese}%{SPACE}%{BASE10NUM:giorno} %{TIME:ora} %{GREEDYDATA}graylog su: %{GREEDYDATA}pam_unix\(su-l:session\):%{GREEDYDATA:stato_sessione}%{SPACE} %{GREEDYDATA}for user root by%{SPACE}%{GREEDYDATA:utente_su}%{GREEDYDATA}\(uid=%{BASE10NUM}\)```
____

## Grok pattern for failed autenthications:

[Lorenzo](https://www.linkedin.com/in/lorenzomagni97/)
