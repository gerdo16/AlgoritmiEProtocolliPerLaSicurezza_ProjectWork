# Protocollo sicuro

## Fase 1: Handshake

U preleva Cert(A) e Cert(S) direttamente da A e li verifica tramite la chiave pubblica della CA ($pk_{CA}$) di riferimento.

Garantisce l'autenticità dei destinatari e prevenire attacchi MIM.

## Fase 2: Certificazione del client + Invio del voto
1. Il client prepara il suo pacchetto in cui deve inviare il suo certificato e direttamente il suo voto
    1. Cifratura Interna: $c = \text{Enc}_{pk_S}(v)$. Il voto è leggibile solo e soltanto da S (nemmeno da A)
    2. Firma del Cifrato: $\sigma = \text{Sign}_{sk_U}(c)$. U garantisce l'integrità del voto cifrato
    3. Cifratura Esterna: $C_{final} = \text{Enc}_{pk_A}(\sigma \| c\| Cert(U))$. Questo C è protetto per A, ed è il pacchetto finale destinato ad A
    
    Questo è lo schema Sign-then-Encrypt che garantisce l'anonimato per chiunque intercetti il pacchetto e poi A saprà solo al limite che l'utente U ha votato (perchè ha il certificato) ma non saprà il voto perchè il voto può decifrarlo solo e soltanto S. Quindi lo schema è StE + Cifratura iniziale.
2. A riceve il packet e agisce come un proxy di sicurezza:
    1. Decifrazione: Usa $sk_A$ per aprire il pacchetto e ottiene quindi $(\sigma \| c\| Cert(U))$
    2. A prende Cert(U) e contatta la CA per verificarlo
    3. A verifica sul database che l'utente non abbia già votato, controllando se era già presente l'hash della sua chiave pubblica (presente nel certificato): ID dell'utente.
    4. Verifica l'identità di U e l'integrità con la firma digitale: A controlla che $V_{pk_U}(c, \sigma) = 1$
    5. A elimina DEFINIIVAMENTE $\sigma$ e Cert(U), interrompendo il legame tra identità e voto
    6. A invia solo $c = \text{Enc}_{pk_S}(v)$ al Server S
    
    Per proteggere la comunicazione $A \to S$, può usare lo schema EtS perchè è CCA secure e non c'è bisogno di garantire l'anonimato perchè si sa che il A è un proxy di sicurezza per S. 
3. Il Server riceve il voto cifrato c ottenendolo rispettando lo schema EtS in destinazione:
    1. Decifrazione Finale: S usa $sk_S$ per ottenere $v = \text{Dec}_{sk_S}(c)$
    2. Il voto v viene conteggiato e registrto
    
    S non può risalire a U perché A non gli ha fornito i dati identificativi.

---

### 3. Analisi dei Requisiti (Obiettivi WP1)

- Confidenzialità (Segretezza): il voto v è cifrato con $pk_S$ fin dall'origine. Nemmeno l'Authenticator A può leggerlo.
- Integrità: Garantita dalla firma di $U$ sul cifrato (StE). Qualsiasi modifica di c durante il tragitto renderebbe la firma $\sigma$ invalida, portando al rigetto immediato da parte di A.
- Autenticità dell'Entità: garantita dai certificati e dalle firme digitali. $A$ è certo dell'identità dell'elettore; $U$ è certo dell'identità del server.
- Anonimato: basato sull'assunzione che A e S non si scambiano informazioni di identità degli elettori.

**S possiede il contenuto ma non l'origin e A possiede l'origine ma non il contenuto.** GODO.

# Problema per il Traffico Temporale
Al punto 2.1, l'utente invia $C_{final} = \text{Enc}_{pk_A}(\sigma \| c \| \text{Cert}(U))$. Quando $A$ decifra il pacchetto (punto 2.2), anziché inoltrare immediatamente $c$ al Server $S$, A usa il suo buffer che è una mappa temporanea.

Dal punto di vista crittografico, se un attaccante estrae la mappa dalla RAM di $A$ durante le elezioni, si trova davanti a questa struttura:
$$\text{Mappa:}\ \text{ID}_U=\text{Hash}(pk_U) \to c$$
Dove $c = \text{Enc}_{pk_S}(v)$. Poiché l'attaccante (e $A$ stesso) non possiede la chiave privata del server ($sk_S$), il contenuto del voto $v$ rimane matematicamente segreto.

Quindi A effettua uno shuffle degli elementi di questa mappa e poi li inoltra a S dopo un certo tempo casuale ma non troppo lungo. Quindi A invia a caso uno dei voti cifrati $c$ al server $S$  ovviamente senza sull'ID dell'utente, in questo modo quando S risponde con un ACK ad A, quest'ultimo saprà esattamente quale voto è stato accettato da S, in questo modo potrà inviare un ACK all'utente U che ha inviato quel voto, senza sapere però quale voto è stato accettato da S e senza che S sappia quale voto è stato inviato da U. 

# Verificabilità Individuale e Struttura dell'Hash Table
Abbiamo detto che usiamo un'hash table per tenere traccia degli utenti che hanno già votato, la chave è l'hash della chiave pubblica di U come ID. Si può pensare di lasciare vuoto il valore associato a questa chiave, però si potrebbe costruire in questo modo:
$$\text{HashTable:}\ \text{ID}_U=\text{Hash}(pk_U) \to Enc_{pk_U}(v)$$
Al massimo un attaccante che compromette A può scoprire chi ha votato (facendo un attacco a dizionario sugli hash delle chiavi pubbliche note degli studenti), ma non potrà mai scoprire COSA l'utente ha votato, perchè serve la chiave segreta di U per decifrare: $Enc_{sk_U}(Enc_{pk_U}(v))=v$
Questo però solo se RSA è probabilisticoco, altrimenti se è deterministico, allora l'attaccante potrebbe costruire un dizionario di voti cifrati per ogni possibile voto (solo SI e NO) e confrontarli con i valori presenti nella hash table, riuscendo così a risalire al voto di ogni utente. Infatti possiamo usare RSA con padding OAEP che è probabilistico.

Questo implica che in $C_{final}$ si deve mandare anche $Enc_{pk_U}(v)$ come ulteriore elemento.