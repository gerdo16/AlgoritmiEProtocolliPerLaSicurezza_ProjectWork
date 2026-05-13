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
2. A riceve il packet e agisce come un proxy (???) di sicurezza:
    1. Decifrazione: Usa $sk_A$ per aprire il pacchetto e ottiene quindi $(\sigma \| c\| Cert(U))$
    2. A prende Cert(U) e contatta la CA per verificarlo
    3. A verifica sul database che l'utente non abbia già votato, controllando se era già presente l'hash del suo certificato.
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