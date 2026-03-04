# Container Security Analyzer

Container Security Analyzer è uno strumento per l’analisi di sicurezza delle immagini container.
Implementa una pipeline modulare che scarica un’immagine, analizza vulnerabilità note, verifica configurazioni del container, ricerca eventuali segreti esposti e produce un report finale consolidato.

La pipeline completa è composta da **5 moduli principali** eseguiti in sequenza.

## Architettura della pipeline

La pipeline esegue i seguenti moduli:

### Module 1 — Image Fetcher

Scarica l'immagine container tramite **Skopeo** e produce tre artefatti principali:

- **OCI image-layout** (usato per analisi configurazione)
- **docker-archive tar** (usato dagli scanner e da **Dive**)
- **filesystem estratto (rootfs)** tramite **umoci unpack**

Output principali:
```bash
outputs/fetched_images/
```
Questo modulo prepara gli artefatti necessari per tutti i moduli successivi.

### Module 2 — Vulnerability Scanner

Esegue la scansione delle vulnerabilità utilizzando due scanner esterni:

- **Trivy**
- **Grype**

Caratteristiche principali:

- scansione dell'immagine tramite **docker-archive**
- normalizzazione dei risultati
- deduplicazione delle vulnerabilità
- merge dei risultati dei due scanner
- analisi delle discrepanze tra scanner
- generazione di report CSV e Markdown

Output:
```bash
outputs/scanner_reports/<image>/
```
Include anche un **vulnerability summary JSON** usato dal modulo di reporting.

### Module 3 — OCI Configuration Checker
Analizza la configurazione dell'immagine utilizzando l'**OCI image layout**.

Verifiche effettuate:

- configurazione dell'immagine
- best practice Docker
- analisi layer tramite **Dive**

Output:
```bash
outputs/checked/<image>/
```
Report generati:
```bash
config_issues.json
config_issues.md
```
Questo modulo non dipende dal metodo di fetch dell'immagine e lavora direttamente sui file OCI locali. 

### Module 4 — Secret Detector

Analizza il filesystem dell'immagine estratta (`rootfs`) alla ricerca di possibili segreti.

Tecniche utilizzate:

- regex per pattern noti (API key, password, JWT, ecc.)
- analisi di **entropia**
- integrazione con:
  - **TruffleHog**
  - **Gitleaks**

Sono esclusi:

- directory di sistema
- file binari

Output:
```bash
outputs/secrets/<image>/
```
Report:
```bash
<image>_secrets.json
<image>_secrets.md
```
### Module 5 — Security Report Generator

Aggrega i risultati dei moduli precedenti e genera un report finale.

Funzionalità:

- normalizzazione dei risultati
- arricchimento delle vulnerabilità con:
  - **Exploit-DB**
  - **CISA Known Exploited Vulnerabilities**
- statistiche aggregate
- grafici SVG interattivi
- ranking dei pacchetti critici
- esportazione in:
  - **HTML interattivo**
  - **PDF**
  - **JSON summary**

Output:
```bash
outputs/report/<image>/
```

## Struttura del progetto

```
container-security-analyzer/
├── fetcher/                        # Modulo 1 – image fetcher (skopeo + umoci)
├── scanner/                        # Modulo 2 – vulnerability scanner
│   ├── expected_fields_trivy.json
│   └── expected_fields_grype.json
├── checker/                        # Modulo 3 – OCI configuration checker
├── secret/                         # Modulo 4 – secret detector
├── report/                         # Modulo 5 – report generator
│
├── pipeline.py                     # Orchestrazione completa dei moduli
├── test.py                         # Runner batch per test su più immagini
│
├── outputs/                        # Artefatti generati dalla pipeline
│
├── requirements.txt                # Librerie Python richieste
└── README.md                       # Istruzioni per eseguire il progetto
```

## Requisiti
### Python
- Python **3.10+**

Installare le dipendenze:
```bash
pip install -r requirements.txt
```
### Strumenti esterni
Devono essere installati e disponibili nel **PATH**:
- skopeo
- umoci
- trivy
- grype
- dive
- trufflehog
- gitleaks
- wkhtmltopdf

## Esecuzione
### Pipeline completa
Esegue l’intera pipeline:
```bash
python pipeline.py --image nginx:latest
```
Opzionale:
```bash
python pipeline.py --image nginx:latest --platform linux/amd64
```
La pipeline esegue automaticamente:
```bash
Modulo 1 → Modulo 2 → Modulo 3 → Modulo 4 → Modulo 5
```

### Esecuzione batch su dataset di immagini
Il file di test esegue la pipeline su più immagini e salva il log completo.
```bash
python test.py
```
Immagini di esempio:
- nginx
- python
- alpine
- dvwa
- centos
- php

Il log completo viene salvato in:
```bash
outputs/full_pipeline_report.txt
```

## Output principali
```
outputs/
├── fetched_images/                # artefatti OCI + tar + rootfs
|── scanner_reports/               # risultati Trivy/Grype/Merged
|── checked/                       # problemi di configurazione
├── secrets/                       # secret detection
└── report/                        # report finale HTML/PDF
```

## Obiettivo del progetto

Questo strumento dimostra come costruire una pipeline completa per:

- analisi delle vulnerabilità
- verifica della configurazione dei container
- detection di segreti
- correlazione con exploit pubblici
- generazione automatica di report di sicurezza

L’obiettivo è fornire una base modulare per **analisi di sicurezza delle immagini container** in contesti di ricerca o DevSecOps.


## Note importanti
- **Riproducibilità**: i risultati dell’analisi possono variare tra esecuzioni diverse. 
  Ciò dipende sia dalla natura dinamica dei **tag delle immagini container** (es. `latest` può riferirsi a versioni differenti nel tempo), sia dagli aggiornamenti continui dei **database di vulnerabilità** utilizzati dagli scanner (Trivy e Grype).
