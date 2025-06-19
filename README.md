# Container Security Analyzer - Exam Version

Questo progetto esegue l'analisi di immagini Docker per identificare vulnerabilità note.

## Struttura

<pre><code>
container-security-analyzer/
|── fetcher/            # Modulo di download immagine
|── scanner/            # Modulo di scanner di vulnerabilità
|── tests/              # Immagini di test
|── requirements.txt    # Librerie Python richieste
|── README.md           # Istruzioni per eseguire il progetto
</pre></code>

## Requisiti

- Python 3.x
- pip
- Docker
- Trivy