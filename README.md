# Grok Patterns (Linux, Windows, Fortinet Fortigate)
The Grok Patterns I wrote to parse Linux, Fortigate and Windows logs during my internship @ ICTeam

You may need to tweak and change them a little to serve your purpose, but since I've noticed there are not many examples of working Grok Patterns on the internet, I hope these can be useful to someone.

If someone tries to become SU and types the wrong password, this is how you can intercept him:

```%{MONTH:mese}%{SPACE}%{BASE10NUM:giorno} %{TIME:ora}%{GREEDYDATA}graylog su: FAILED SU \(to root\)%{GREEDYDATA:utente_fallito_su}%{GREEDYDATA}on pts/0```

[Lorenzo](https://www.linkedin.com/in/lorenzomagni97/)
