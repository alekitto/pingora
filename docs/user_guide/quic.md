# Servizio QUIC

Il servizio QUIC di Pingora fornisce un listener UDP basato su [`quiche`](https://github.com/cloudflare/quiche) che termina le connessioni in ingresso e le abbina a un backend selezionato tramite il `LoadBalancer`. Questa guida illustra i prerequisiti, come configurare certificati e listener e quali limiti e strategie operative tenere presenti.

## Prerequisiti e abilitazione delle feature

* Il supporto è disponibile solo compilando con la feature `quic`, che attiva il binding a `quiche` sia in `pingora-core` sia in `pingora-load-balancing`.
* Per utilizzare le ricette del bilanciatore occorre aggiungere anche la feature `lb` quando si eseguono esempi o binari.
* Il listener richiede certificati TLS 1.3 in formato PEM.

Esempio di comando per lanciare un binario con entrambe le feature:

```bash
cargo run -p pingora --example quic_lb --features "lb quic"
```

## Configurazione del trasporto e dei certificati

Costruire il `ServerConfig` partendo da `TransportConfigBuilder` consente di caricare certificato e chiave privata in PEM e di definire la lista ALPN annunciata ai client. Dopo la creazione è possibile abilitare esplicitamente il supporto ai datagrammi QUIC:

```rust
use pingora_core::protocols::quic::TransportConfigBuilder;

let mut builder = TransportConfigBuilder::new()?;
builder = builder
    .load_cert_chain_from_pem_file(cert_path)?
    .load_priv_key_from_pem_file(key_path)?
    .application_protos(&[b"h3"])?
    .verify_peer(false);
let server_config = builder.build_server()?;
server_config
    .transport()
    .with_config_mut(|cfg| cfg.enable_dgram(true, 32, 32))?;
```

Lo stesso approccio vale per la configurazione client nei test o nei connettori QUIC. Le chiavi devono essere coerenti con quelle presentate dai backend e con i vincoli di sicurezza dell'ambiente di esecuzione.

## Integrazione con il LoadBalancer

`LoadBalancer` implementa il trait `QuicBackendSelector`, quindi può essere passato direttamente al costruttore del servizio. I backend QUIC vengono dichiarati con il prefisso `quic://` e mantengono le stesse proprietà (peso, metadati) degli altri protocolli supportati.

```rust
use pingora_load_balancing::{Backend, LoadBalancer};
use pingora_load_balancing::selection::RoundRobin;
use pingora_core::services::quic::QuicService;

let backends = vec![Backend::new_quic("quic://127.0.0.1:9443")?];
let lb = LoadBalancer::<RoundRobin>::try_from_iter(backends)?;
let selector = std::sync::Arc::new(lb) as std::sync::Arc<dyn QuicBackendSelector>;

let mut service = QuicService::new("QUIC LB", listen_addr, server_config, selector);
service.set_max_backend_iterations(8);
```

È possibile personalizzare le opzioni del socket UDP e i limiti delle code di ricezione/trasmissione per adattarsi al carico previsto.

## Esempio completo

L'esempio `quic_lb` mostra come avviare un server Pingora che ascolta su QUIC, popola un bilanciatore round robin e collega la selezione del backend al servizio. I percorsi di certificato e chiave predefiniti riutilizzano il materiale di test incluso nel repository e possono essere sovrascritti da riga di comando.

```bash
cargo run -p pingora --example quic_lb \
    --features "lb quic" \
    -- --listen 0.0.0.0:4433 \
    --backend quic://10.0.0.10:4433 --backend quic://10.0.0.11:4433
```

## Health check e fallback

Al momento i checker integrati non supportano le sonde QUIC native: invocare un health check su un backend con protocollo QUIC restituisce l'errore `quic_health_check_unavailable`. È quindi consigliabile:

* Delegare il monitoraggio a un sistema esterno (ad esempio Prometheus o un orchestratore) che aggiorni lo stato dei backend tramite discovery dinamica.
* Oppure effettuare un controllo UDP/TCP di portata ridotta sugli stessi host per mantenere il ciclo di vita allineato.

Quando un backend QUIC diventa indisponibile si può usare `LoadBalancer::select_with_protocol` per cadere su endpoint TCP (HTTP/1.1 o HTTP/2) già esistenti, oppure istruire l'applicazione a degradare il traffico verso un servizio HTTP tradizionale mantenendo il tracciamento del client.

## Limiti noti

* Il servizio termina il trasporto QUIC e demanda al backend selezionato la logica applicativa (HTTP/3, gRPC, ecc.); non esiste ancora un'integrazione diretta con gli handler HTTP inclusi in Pingora.
* Non sono disponibili health check QUIC first-party.
* La configurazione richiede certificati TLS in formato PEM caricabili da disco.
* L'abilitazione della feature `quic` comporta la compilazione del crate `quiche`, che potrebbe richiedere toolchain C compatibili sul sistema di build.
