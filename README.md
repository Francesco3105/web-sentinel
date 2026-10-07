# Web Sentinel

Tool interno per monitorare i siti web in gestione: disponibilità,
funzionalità, traffico, integrità dei file e segnali di malware, con alert automatici via mail.

Web Sentinel riduce i tempi di rilevamento dei problemi; non garantisce la sicurezza dei siti.


## Stato

**Fase 1 – Fondamenta**: struttura del progetto, database e migrazioni, inventario dei siti,
accesso con ruoli, audit log, layout dell'interfaccia.

**Fase 2 – Monitoraggio attivo e alert**: controlli `http`, `dns`, `tls` e `domain` eseguiti
dal worker sui siti attivi e autorizzati; incidenti aperti e chiusi in automatico; mail di alert
con promemoria e recovery; Panoramica, scheda sito con tempo di risposta e uptime, Incidenti.

## Avvio in locale, senza Docker

Per i PC dove Docker non è disponibile: Python 3.12 o successivo e un file SQLite in `.local/`.

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

## Incidenti e mail di alert

- Un controllo che fallisce viene ripetuto dopo un minuto; al terzo fallimento consecutivo si apre
  un incidente critico. Se sullo stesso sito falliscono più controlli insieme, finiscono tutti
  nello stesso incidente: un sito irraggiungibile produce una sola serie di mail.
- Un certificato che scade entro 7 giorni apre un incidente di attenzione. Una risposta lenta
  compare nell'interfaccia ma non apre incidenti e non genera mail.
- Un dominio che scade entro 30 giorni apre un incidente di attenzione, entro 7 giorni critico,
  con un promemoria al giorno. La scadenza si legge via RDAP e, dove manca, via WHOIS: sono
  richieste ai registri, non al sito. Se non è determinabile il controllo segnala attenzione
  senza aprire incidenti.
- Critico: una mail subito, a qualsiasi ora, un promemoria ogni 30 minuti e una mail di rientro
  con la durata. Attenzione: mail solo tra le 08:00 e le 20:00, non ripetuta per lo stesso
  problema entro 6 ore, più la mail di rientro.
- Ogni invio, riuscito o no, è elencato nella scheda dell'incidente. Un invio fallito viene
  ritentato dopo 5 minuti.

Fuori produzione (`ENVIRONMENT` diverso da `production`) le mail restano in Mailpit. Per provare
un invio reale, ad esempio con Resend, impostare in `.env`:

```
SMTP_HOST=smtp.resend.com
SMTP_PORT=587
SMTP_USER=resend
SMTP_PASSWORD=<chiave API>
SMTP_FROM=Web Sentinel <mittente@dominio-verificato>
MAIL_REAL_DELIVERY=true
MAIL_TEST_RECIPIENT=<indirizzo di prova>
```

Con `MAIL_REAL_DELIVERY=true` fuori produzione tutte le mail vanno soltanto a
`MAIL_TEST_RECIPIENT`, mai ai destinatari configurati. In produzione valgono i parametri `SMTP_*`
e i destinatari veri. Dopo una modifica a `.env` ricreare i servizi con `docker compose ... up -d`.

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
