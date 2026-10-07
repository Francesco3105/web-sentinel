# Web Sentinel

Web Sentinel tiene sotto controllo un insieme di siti web e avvisa via mail quando qualcosa non
va: sito irraggiungibile, errore del server, DNS che non risolve, certificato o dominio in
scadenza. È pensato per chi gestisce alcune decine di siti e vuole sapere di un problema prima
che lo segnali un cliente.

Riduce i tempi di rilevamento dei problemi; non garantisce la sicurezza dei siti e non sostituisce
la verifica diretta.

> **In sviluppo: non è pronto per la produzione.** Sono completate due fasi su sei e la
> revisione di sicurezza del codice è prevista solo nell'ultima (vedi [Stato](#stato-e-piano)).

## Come funziona

```
 siti (HTTP, DNS, TLS) ◄── worker ──► database ◄── web (interfaccia)
 registri (RDAP, WHOIS) ◄────┘  │
                                └──► server SMTP ──► mail di alert
```

Il sistema è fatto di tre servizi:

- **web**: l'interfaccia, dove si gestisce l'inventario dei siti e si consultano esiti e incidenti;
- **worker**: un processo separato che ogni pochi secondi esegue i controlli arrivati a scadenza,
  apre e chiude gli incidenti e spedisce le mail;
- **db**: PostgreSQL, dove finisce tutto lo storico.

### 1. Inventario e autorizzazione

Ogni sito ha nome, URL, criticità, referenti e un'**autorizzazione al monitoraggio** (chi l'ha
data e quando). Finché l'autorizzazione non è registrata nella scheda del sito nessun controllo
parte: il sistema non interroga mai bersagli che non siano in inventario e autorizzati.

### 2. Controlli

Per ogni sito il worker esegue controlli periodici. Sono richieste normali (una GET, una
risoluzione DNS, un handshake TLS): niente scansioni né tentativi di accesso.

| Controllo | Cosa verifica | Ogni | Esito |
|---|---|---|---|
| HTTP/HTTPS | il sito risponde, con quale codice e in quanto tempo | 5 min | errore se non risponde entro 120 s o risponde con 4xx/5xx; attenzione oltre 30 s |
| DNS | il nome risolve (e, se indicati, agli indirizzi attesi) | 10 min | errore se non risolve; attenzione se diverso dall'atteso |
| Certificato TLS | catena valida, nome corretto, giorni alla scadenza | 6 ore | errore se scaduto o non valido; attenzione sotto 30 giorni |
| Scadenza dominio | data di scadenza letta dai registri (RDAP, poi WHOIS) | 24 ore | errore se scaduto; attenzione sotto 30 giorni |

Il controllo del dominio si può disattivare per sito: serve per i sottodomini la cui
registrazione è gestita da altri. Intervalli e soglie sono salvati nel database, per controllo.

### 3. Incidenti

Un singolo controllo fallito non basta a dare l'allarme:

- un controllo fallito viene ripetuto dopo un minuto; al **terzo fallimento consecutivo** si apre
  un incidente critico;
- se sullo stesso sito falliscono più controlli insieme (un sito giù fa fallire HTTP, DNS e TLS)
  finiscono tutti nello **stesso incidente**;
- un certificato che scade entro 7 giorni, o un dominio entro 30, apre un incidente di
  attenzione; un dominio entro 7 giorni un incidente critico;
- una risposta lenta compare nell'interfaccia ma non apre incidenti;
- l'incidente **si chiude da solo** quando i controlli tornano regolari.

### 4. Mail di alert

| Gravità | Quando parte | Ripetizione | Rientro |
|---|---|---|---|
| Critico | subito, a qualsiasi ora | promemoria ogni 30 minuti (uno al giorno per il dominio) | mail con la durata |
| Attenzione | subito, ma solo tra le 08:00 e le 20:00 | nessuna; non ripetuta per lo stesso problema entro 6 ore | mail di rientro |

Ogni mail riporta sito, problema, orario, ultimo esito, azione consigliata e link all'incidente.
Ogni invio, riuscito o no, è elencato nella scheda dell'incidente; un invio fallito viene
ritentato dopo 5 minuti senza fermare il worker.

### 5. Interfaccia

- **Panoramica**: siti operativi, incidenti aperti, uptime degli ultimi 30 giorni, scadenze entro
  30 giorni, siti ordinati per gravità.
- **Siti**: inventario; nella scheda di ogni sito i controlli con l'ultimo esito, il tempo di
  risposta delle ultime 24 ore, l'uptime e gli incidenti aperti. I controlli si possono anche
  lanciare a mano.
- **Incidenti**: elenco filtrabile; in ogni scheda cronologia, azione consigliata e mail inviate.
- **Utenti** e **Audit log** (solo amministratori).

Lo stato non è mai affidato al solo colore: ogni etichetta ha un'icona e un testo. L'interfaccia
si usa anche da telefono.

### Ruoli e sicurezza

| Ruolo | Permessi |
|---|---|
| Amministratore | tutto: inventario siti, utenti, audit log |
| Operatore | consultazione ed esecuzione manuale dei controlli |
| Sola lettura | consultazione |

Password con hash Argon2, sessioni con cookie `HttpOnly`, protezione CSRF, limite ai tentativi di
accesso. Ogni azione amministrativa è registrata nell'audit log, che non è modificabile: su
PostgreSQL il database rifiuta modifiche e cancellazioni sulle sue righe.

## Cosa serve

- **Docker** con Docker Compose (consigliato), oppure Python 3.12 o successivo per l'avvio senza
  Docker.
- **Un server SMTP** per spedire le mail di alert: quello aziendale o un servizio come Resend.
  In sviluppo non serve: le mail finiscono in Mailpit, incluso nel Compose di sviluppo.
- **Accesso in uscita** dal server verso i siti da controllare (porte 80 e 443), verso il DNS e
  verso i registri dei domini (RDAP su 443, WHOIS su 43).
- **Un file `.env`** con le impostazioni, ricavato da `.env.example`. Non va mai messo nel
  repository.

Se un sito è protetto da firewall o WAF, conviene mettere in allowlist l'indirizzo del server e
lo user agent dei controlli: `WebSentinel/1.0 (monitoraggio interno)`.

## Avvio con Docker

1. Copiare `.env.example` in `.env` e compilare almeno `POSTGRES_PASSWORD`, `SECRET_KEY`,
   `IP_HMAC_KEY`, `ADMIN_EMAIL` e `ADMIN_PASSWORD` (minimo 12 caratteri in produzione). Per lo
   sviluppo impostare `ENVIRONMENT=development`.
2. Avviare i servizi; le migrazioni del database vengono applicate all'avvio:

   ```
   docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build -d
   ```

3. Caricare i dati iniziali (siti di esempio, regole di alert, primo amministratore):

   ```
   docker compose -f docker-compose.yml -f docker-compose.dev.yml exec web python scripts/seed.py
   ```

4. Aprire <http://localhost:8000> ed entrare con `ADMIN_EMAIL` e `ADMIN_PASSWORD`.
   Le mail di sviluppo si leggono in Mailpit: <http://localhost:8025>.
5. Aggiungere i propri siti da **Siti → Aggiungi sito** e registrare l'autorizzazione nella
   scheda di ciascuno: da quel momento i controlli partono da soli.

I siti caricati dal seed sono esempi sui domini riservati alla documentazione e nascono senza
autorizzazione. Dopo ogni modifica a `.env` i servizi vanno ricreati con lo stesso comando `up`.

## Avvio senza Docker

Per provare il progetto dove Docker non è disponibile: usa un file SQLite in `.local/` al posto
di PostgreSQL.

```
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
.venv\Scripts\python.exe scripts\run_local.py
```

Lo script applica le migrazioni, carica i dati iniziali, avvia il worker e apre l'interfaccia su
<http://localhost:8000>. Su Linux e macOS i percorsi sono `.venv/bin/python`.

## Configurazione

Tutte le impostazioni stanno in `.env`; `.env.example` le elenca con un commento. Le principali:

| Variabile | A cosa serve |
|---|---|
| `ENVIRONMENT` | `production` oppure `development` |
| `APP_TIMEZONE` | fuso orario di orari e finestre di invio (predefinito `Europe/Rome`) |
| `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | credenziali del database |
| `SECRET_KEY` | firma dei cookie di sessione |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | primo amministratore, creato dal seed |
| `ALERT_DEFAULT_RECIPIENT` | destinatario di tutti gli alert |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_TLS`, `SMTP_FROM` | server di posta |
| `APP_BASE_URL` | indirizzo dell'interfaccia, usato per i link nelle mail |
| `INCIDENT_FAILURE_THRESHOLD` | fallimenti consecutivi prima di aprire un incidente (3) |
| `FAILURE_RETRY_SECONDS` | attesa prima di ripetere un controllo fallito (60) |
| `MAIL_REAL_DELIVERY`, `MAIL_TEST_RECIPIENT` | invio reale fuori produzione, vedi sotto |

### Mail in sviluppo e invio reale

Fuori produzione le mail restano in Mailpit e nessuna mail reale viene spedita. Per provare la
consegna vera, ad esempio con Resend, impostare in `.env`:

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
e i destinatari veri.

## Comandi utili

Con Docker, anteponendo `docker compose -f docker-compose.yml -f docker-compose.dev.yml`:

```
exec web alembic upgrade head            # migrazioni
exec web python scripts/seed.py          # dati iniziali (ripetibile)
exec web pytest                          # test, su un database <nome>_test
exec web sh -c "ruff check . && ruff format --check . && mypy app"   # qualità
logs -f worker                           # cosa sta facendo il worker
down                                     # ferma tutto (i dati restano nel volume)
```

## Struttura del progetto

```
app/
  main.py        applicazione web (FastAPI)
  config.py      impostazioni lette da .env
  db/            modelli, sessioni, migrazioni Alembic, dati iniziali
  checks/        controlli: http, dns, tls, dominio
  worker/        ciclo del worker ed esecuzione dei controlli
  incidents/     apertura e chiusura degli incidenti
  alerts/        regole di invio, deduplica, template delle mail, SMTP
  auth/          accesso, ruoli, audit log
  ui/            pagine, template, CSS, font
tests/           test automatici
scripts/         seed e avvio locale
```

Stack: Python 3.12, FastAPI, SQLAlchemy con Alembic, PostgreSQL 16, template Jinja2 con CSS
scritto a mano, grafici SVG generati dal server.

## Stato e piano

| Fase | Contenuto | Stato |
|---|---|---|
| 1 | Fondamenta: inventario, accesso con ruoli, audit log, interfaccia | fatta |
| 2 | Monitoraggio attivo e alert: controlli, incidenti, mail, panoramica | fatta |
| 3 | Controlli funzionali (endpoint, contenuto, flussi), silenziamenti, manutenzioni, destinatari per sito | da fare |
| 4 | Agent sui server dei siti: integrità dei file, euristiche webshell, antivirus | da fare |
| 5 | Analisi dei log e anomalie di traffico, reputazione | da fare |
| 6 | Report periodici, backup, auto-monitoraggio, revisione di sicurezza | da fare |

Limiti attuali da conoscere:

- le azioni manuali sugli incidenti (presa in carico, note, chiusura) non ci sono ancora;
- il worker non controlla sé stesso: se si ferma, l'interfaccia lo mostra ma non parte una mail;
- la messa in produzione (reverse proxy, HTTPS, backup) non è ancora documentata.

## Licenza

[MIT](LICENSE). I font IBM Plex in `app/ui/static/fonts` sono distribuiti con licenza SIL Open
Font License (vedi `OFL.txt` nella stessa cartella).
