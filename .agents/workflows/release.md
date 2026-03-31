---
description: Interaktiver Release-Prozess für den ioBroker Adapter
---

# Release Workflow

Dieser Workflow beschreibt, wie ein Release **gemeinsam mit dem AI-Assistenten** durchgeführt wird.
Er kombiniert maximale Automatisierung mit einer gezielten manuellen Review-Phase.

## Voraussetzungen

Bevor du den Workflow startest, stell sicher, dass:

- Alle geplanten Änderungen committed und gepusht sind
- Du auf dem `main`-Branch bist
- Das Working Tree sauber ist (`git status`)

---

## Schritt 1 – Release vorbereiten (AI-Aufgabe)

Sage dem Assistenten, dass du einen Release machen möchtest. Er übernimmt dann automatisch:

1. **Änderungen seit dem letzten Tag ermitteln:**

```bash
git log $(git describe --tags --abbrev=0)..HEAD --oneline
```

2. **Aktuellen Stand prüfen** (Version, offene Issues, Changelog-Platzhalter in README.md)

3. **Repository-Check durchführen:**
   Der Assistent führt den `repochecker` aus, um sicherzustellen, dass keine formalen Fehler vorliegen:

   ```bash
   npx @iobroker/repochecker TA2k/ioBroker.mihome-cloud
   ```

   _Hinweis: Fehler `E2004` (Version noch nicht auf NPM) und Warnung `W2002` (Versions-Mismatch) können ignoriert werden, da diese erst NACH dem Release verschwinden._

4. **Changelog-Einträge formulieren:**
   Der Assistent schlägt saubere, präzise Changelog-Sätze vor, die du bestätigst oder anpasst.

5. **Changelog in README.md eintragen:**
   Der Assistent trägt die Änderungen **direkt unter** dem Platzhalter `### **WORK IN PROGRESS**` ein.
   **WICHTIG:** Erstelle _keinen_ manuellen Header mit der neuen Versionsnummer (z.B. `### 0.1.8`), da das Release-Script diesen Header selbst generiert und sonst mit einem Fehler ("Changelog is empty") abbricht.

6. **Änderungen committen (WICHTIG):**
   Bevor das Release-Script gestartet wird, muss der Assistent **alle** ausstehenden Änderungen (README.md, Workflows, .gitignore, etc.) committen und pushen. Das Release-Script prüft auf einen sauberen Git-Status und bricht bei jeder kleinsten Änderung ab.
   ```bash
   git add . && git commit -m "chore: preparations for vX.Y.Z" && git push
   ```

---

## Schritt 2 – Release-Script starten

Wenn Changelog und Version abgesegnet sind, startet der Assistent das Release-Script:

// turbo

```bash
npm run release -- patch
```

_(oder `minor`/`major` je nach Release-Typ)_

Das Script läuft automatisch durch:

- ✅ **Lint-Check** (`npm run lint`) – bricht sofort ab wenn Fehler
- ✅ **Tests** (`npm test`) – bricht sofort ab wenn Tests fehlschlagen
- ✅ Lizenz-Check
- ✅ Version in `package.json` bumpen
- ✅ Version + News in `io-package.json` setzen
- ✅ Changelog-Einträge in alle 11 ioBroker-Sprachen übersetzen
- ⏸️ **PAUSE** – `manual-review` hält den Prozess an

---

## Schritt 3 – Manuelle Review (gemeinsam)

Während der Pause prüfen wir gemeinsam die generierten Änderungen:

Der Assistent liest automatisch die modifizierten Dateien und gibt dir einen Überblick:

- `README.md` – Changelog korrekt?
- `io-package.json` – Übersetzungen plausibel? News-Einträge vollständig?
- `package.json` – Versionsnummer stimmt?

Wenn alles passt: **Enter drücken** im Terminal, um den Release abzuschließen.
Bei Problemen: Im Terminal **Ctrl+C** abbrechen und Korrekturen vornehmen.

---

## Schritt 4 – Automatischer Abschluss

Nach der Bestätigung läuft alles automatisch:

- ✅ Git-Commit mit allen Änderungen
- ✅ Git-Tag `vX.Y.Z` erstellen
- ✅ Push zu GitHub (löst CI/CD aus)
- ✅ GitHub Actions baut und veröffentlicht auf NPM
- ✅ Neuer leerer Changelog-Platzhalter wird in README.md eingefügt

---

## Hinweise

- **DeepL statt ioBroker Translator:** Für bessere Übersetzungen kann `DEEPL_API_KEY` gesetzt werden.
- **Nur Tag pushen** (bei Branch-Protection): `npm run release -- patch --tagOnly`
- **Prerelease:** Für Alpha/Beta-Versionen `npm run release -- patch --preid alpha`
