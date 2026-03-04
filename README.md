# Container Security Analyzer - Exam Version

Questo progetto esegue l'analisi di immagini Docker per identificare vulnerabilità note.
Offre una pipeline minima per **Image Fetcher** + **Vulnerability Scanner** su immagini Docker pubbliche mediante Trivy e Grype, con normalizzazione, merge e report CSV/Markdown.

## Struttura

<pre><code>
container-security-analyzer/
|── fetcher/            # Modulo di download immagine
|── scanner/            # Modulo di scanner di vulnerabilità
|── tests/              # Immagini di test
|── requirements.txt    # Librerie Python richieste
|── README.md           # Istruzioni per eseguire il progetto
</pre></code>

## Contenuti
- `fetcher/`: fetch e salvataggio immagine (`docker save`) con estrazione layer sicura opzionale.
- `scanner/`: invocazione Trivy/Grype, normalizzazione output, report, merge e confronti.
- `tests/`: script batch per dataset di immagini e pipeline end-to-end.
- `outputs/`: artefatti generati.

## Requisiti

- **Python 3.10+**
- **Docker** in esecuzione (CLI e daemon)
- **Trivy** e **Grype** installati nel PATH (scanner esterni)
- Python: vedi `requirements.txt`

## Esecuzione — 2 modalità

### A) Scanner “da tag” (richiama direttamente i tool)
Esegue Trivy/Grype con il nome dell’immagine.
```bash
python tests/test_scan_images.py
```

### B) Pipeline “da archivio” (fetch → tar → scan dallo stesso TAR)
Congela l’input con `docker save` e poi scansiona `--input`/`docker-archive:` per massima riproducibilità.
```bash
python tests/test_pipe.py
```

Gli output vengono scritti in `outputs/` (sottocartelle Trivy/Grype/Merged; *_ARC per la modalità archivio).

## Note importanti
- **Deduplicazione** su chiave `(CVE, PkgName, InstalledVersion)` per evitare conteggi gonfiati.
- **Sicurezza** nell’estrazione tar: `safe_mode=True` impedisce path traversal.
- **Riproducibilità**: preferire scansione da `tar` per evitare drift dei tag; i DB di Trivy/Grype evolvono quotidianamente.
