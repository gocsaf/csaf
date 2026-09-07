<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
-->

# Vergleich der JSON-Schema-Generatoren

Dieses Verzeichnis enthält die reproduzierbaren Läufe zur Generator-Tabelle in
`docs/csaf-2.0-to-2.1-port.md`.

- `logs/` enthält pro getesteter Bibliothek eine Textdatei mit allen zugehörigen
  Befehlen, deren Standardausgabe, Fehlerausgabe und Exit-Status. Mehrere Versuche
  derselben Bibliothek, etwa Generierung und Kompilierprüfung oder ein Lauf mit
  zusätzlichen lokalen Referenzen, stehen gemeinsam in dieser Datei.
- `logs/schema-preparation.txt` und `logs/environment.txt` dokumentieren die
  gemeinsam verwendeten Eingaben beziehungsweise die Laufzeitumgebung.
- `run-generators.sh` erzeugt den Hauptvergleich aus dem vorbereiteten CSAF-Schema.
- `run-followups.sh` prüft die naheliegende Abhilfe, alle externen Referenzen lokal
  mitzugeben, und kompiliert die Ausgabe von emersion/go-jsonschema.
- `input/` enthält die vorbereiteten OASIS-Root-Schemata und das lokale ROLIE-Schema.
- `input-with-references/` enthält zusätzlich die rekursiv geladenen externen
  Schemata.
- `output/` enthält jede tatsächlich geschriebene Generatorausgabe. Fehlt die
  erwartete Datei oder bleibt ein Verzeichnis leer, hat der betreffende Generator
  vor der Ausgabe abgebrochen oder trotz Erfolgsmeldung kein Modell erzeugt.

Die Bibliotheksprotokolle sind:

- [`go-jsonschema.txt`](logs/go-jsonschema.txt): Modellerzeugung und
  Validierungserzeugung, jeweils mit Kompilierprüfung.
- [`quicktype.txt`](logs/quicktype.txt): Modellerzeugung.
- [`modelina.txt`](logs/modelina.txt): Modellerzeugung.
- [`schemagen.txt`](logs/schemagen.txt): Modellerzeugung und Kompilierprüfung,
  jeweils mit dem Root-Schema und mit allen lokalen Referenzen.
- [`esdigo.txt`](logs/esdigo.txt): Modellerzeugung mit dem Root-Schema und mit
  allen lokalen Referenzen.
- [`christopherdavenport-jsonschema.txt`](logs/christopherdavenport-jsonschema.txt):
  Advisory- und ROLIE-Erzeugung sowie die ROLIE-Kompilierprüfung.
- [`emersion-go-jsonschema.txt`](logs/emersion-go-jsonschema.txt):
  Modellerzeugung und Kompilierprüfung.

Die OASIS-Eingabe ist auf Commit
`fd04963f836406b2691c861feb80db58577fc9c7` fixiert. Fremde Generatoren liefen
isoliert in den unter `logs/` dokumentierten Docker-Images.

Der Vergleich unterscheidet bewusst zwei Klassen von Reparaturen:

1. Eine begrenzte Modellkorrektur ersetzt eine bekannte, exakt erwartete Stelle
   in ansonsten kompilierendem Code. Die Schema-Validierung bleibt davon unberührt.
2. Eine Generatorreparatur ändert allgemeine Namensbildung, Referenzauflösung,
   Typprojektion oder Validierungssemantik. Sie verlangt einen gepflegten Fork oder
   ein werkzeugspezifisch verändertes Eingabeschema.

Nur die erste Klasse wird für die gewählte go-jsonschema-Modellausgabe verwendet.
