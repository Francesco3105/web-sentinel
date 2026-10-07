# Web Sentinel

Tool interno per monitorare i siti web in gestione: disponibilità,
funzionalità, traffico, integrità dei file e segnali di malware, con alert automatici via mail.

Web Sentinel riduce i tempi di rilevamento dei problemi; non garantisce la sicurezza dei siti.


## Stato

**Fase 1 – Fondamenta**: struttura del progetto, database e migrazioni, inventario dei siti,
accesso con ruoli, audit log, layout dell'interfaccia.

**Fase 2 – in corso**: controlli `http`, `dns` e `tls` eseguiti dal worker sui siti attivi e
autorizzati, esiti nella scheda sito, colonna Stato, pulsante "Esegui controlli ora". Mancano il
controllo `domain`, gli incidenti e le mail di alert.

## Avvio in locale, senza Docker

È il modo usato oggi per lo sviluppo: Python 3.12 o successivo e un file SQLite in `.local/`.

```
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
.venv\Scripts\python.exe scripts\run_local.py
```

Lo script applica le migrazioni, carica i dati iniziali, avvia il worker e apre il servizio su
<http://localhost:8000>. Serve il file `.env` (vedi sotto). Test e controlli di qualità:

```
.venv\Scripts\python.exe -m pytest
.venv\Scripts\ruff.exe check . ; .venv\Scripts\ruff.exe format --check . ; .venv\Scripts\mypy.exe app
```

## Avvio con Docker

Non ancora verificato: sul PC di sviluppo Docker non è disponibile. Va provato sull'ambiente finale.
Servono Docker Engine con Compose e git.

1. Copiare `.env.example` in `.env` e compilare almeno `POSTGRES_PASSWORD`, `SECRET_KEY`,
   `IP_HMAC_KEY`, `ADMIN_EMAIL`, `ADMIN_PASSWORD` (minimo 12 caratteri). In sviluppo impostare
   `ENVIRONMENT=development`. Il file `.env` non va mai messo nel repository.
2. Avviare i servizi (le migrazioni vengono applicate all'avvio di `web`):

   ```
   docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
   ```

3. Caricare i dati iniziali (siti di esempio, regole di alert, primo amministratore):

   ```
   docker compose exec web python scripts/seed.py
   ```

4. Aprire <http://localhost:8000> ed entrare con `ADMIN_EMAIL` / `ADMIN_PASSWORD`.
   Le mail di sviluppo finiscono in Mailpit: <http://localhost:8025>. Nessuna mail reale viene spedita.

## Comandi

```
docker compose exec web alembic upgrade head                 # migrazioni
docker compose exec web python scripts/seed.py               # dati iniziali (ripetibile)
docker compose exec web pytest                               # test (usa un database <nome>_test)
docker compose exec web sh -c "ruff check . && ruff format --check . && mypy app"   # qualità
```

## Ruoli

| Ruolo | Permessi |
|---|---|
| Amministratore | tutto: inventario siti, utenti, audit log |
| Operatore | gestione di incidenti, silenziamenti e controlli (dalla fase 2) |
| Sola lettura | consultazione |

Ogni azione amministrativa è registrata nell'audit log, che non è modificabile: il database
rifiuta modifiche e cancellazioni sulle sue righe.

## Autorizzazione dei siti

I controlli partono solo per i siti attivi con autorizzazione registrata (chi l'ha data e quando),
da compilare nella scheda del sito. I siti caricati dal seed nascono senza autorizzazione.

## Produzione

Da completare nella fase 6. In sintesi: `docker compose up -d` senza il file di sviluppo,
`SESSION_COOKIE_SECURE=true`, servizio `web` esposto solo tramite il reverse proxy aziendale
(HTTPS, rete interna/VPN).
