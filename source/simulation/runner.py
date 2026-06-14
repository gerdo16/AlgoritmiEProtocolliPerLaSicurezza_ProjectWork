from actors.user import User
from actors.certificationauthority import CertificationAuthority
from actors.authenticator import Authenticator
from actors.server import Server

def runFullProtocol():
    """ Esegue l'intero protocollo di votazione simulando dalla prima fase preliminare fino alla verifica individuale del voto """

    print("\n\n================================================================================================================")
    print("================================== Inizio simulazione protocollo di votazione ==================================")
    print("================================================================================================================\n\n")


    print("===================================================== Fase preliminare del sistema ==========================================================")
    ca = CertificationAuthority("University Voting CA", "vote.unisa.it")
    ca.autoSignCertificate()

    authenticator = Authenticator("University Voting Authenticator", "authenticate.unisa.it")
    authenticator.setCertificationAuthority(ca)
    authenticator.generateKeyPair()
    authenticator.generateUnsignedCertificate()
    authenticator.signCertificateWithCA()

    server = Server("University Voting Server", "vote.unisa.it")
    server.setCertificationAuthority(ca)
    server.generateKeyPair()
    server.generateUnsignedCertificate()
    server.signCertificateWithCA()

    if authenticator.verifyCertificate(server.getCertificate()):
        authenticator.setCAServerCertificate(server.getCertificate())
    if server.verifyCertificate(authenticator.getCertificate()):
        server.setCAAuthenticatorCertificate(authenticator.getCertificate())    

    print()

    tmp_list:list[tuple[str, str]] = [
        ("Pippo", "IE22700086"),
        ("gerry", "IE22700089"),
        ("sava", "IE22800290"),
        ("Luca", "IE22800391"),
        ("Gino", "IE22800692"),
        ("Mario", "IE22800993"),
        ("Francesco", "IE22801294"),
        ("Giovanni", "IE22801595"),
        ("Simone", "IE22801896")
    ]
    list_users:list[User] = []
    [list_users.append(User(name, matriculation_number)) for name, matriculation_number in tmp_list]
    [curr_user.setCertificationAuthority(ca) for curr_user in list_users]

    singleUserVotatingProcess(list_users[0], authenticator, server, verbose=True)
    [singleUserVotatingProcess(curr_user, authenticator, server, verbose=False) for curr_user in list_users[1:]]

    singleUserIndividualVerification(list_users[0], authenticator, verbose=True)
    [singleUserIndividualVerification(curr_user, authenticator, verbose=False) for curr_user in list_users[1:]]


    print("\n\n===================================================== Fase Verificabilità universale ==========================================================")
    result_package:bytes = server.publishResults(verbose=True)
    list_users[0].universalVerification(result_package, verbose=True)
    [user.universalVerification(result_package, verbose=False) for user in list_users[1:]]


    print("\n\n================================================================================================================")
    print("=================================== Fine simulazione protocollo di votazione ===================================")
    print("================================================================================================================\n\n")



def singleUserVotatingProcess(user, authenticator, server, verbose: bool = True):
    """ Simula il processo di votazione di un singolo utente """

    print(f"\n\nStampa completa del processo di votazione per l'utente \"{user.name}\"") if verbose else print(f"\n\nStampa sintetica del processo di votazione per l'utente \"{user.name}\"")
    print(f"================================================== Fase certificato utente \"{user.name}\" =======================================================")
    user.generateKeyPair(verbose)
    user.generateUnsignedCertificate(verbose)
    user.signCertificateWithCA(verbose)


    print(f"\n\n================================================== Fase di handshake \"{user.name}\" =======================================================")
    user.voteRequestSend(authenticator, verbose)
    user.verifyCertificates(verbose)


    print(f"\n\n================================================== Fase trasmissione voto \"{user.name}\" =======================================================")
    print("\n================ Fase trasmissione voto: U -> A ================") if verbose else None
    C_final:list[bytes] = user.createCfinal(verbose)

    print("\n================ Fase verifica certificato utente e validazione C_final ================") if verbose else None
    authenticator.receiveCfinal(C_final, verbose)
    authenticator.bufferingVote(verbose)

    print("\n================ Fase preparazione pacchetto e inoltro voto: A -> S ================") if verbose else None
    pck_to_server:bytes = authenticator.sendPckToServer(verbose)
    pck_to_authenticator:bytes = server.receivePckFromAuthenticator(pck_to_server, verbose)

    print("\n================ Fase ricezione ACK dell'Authenticator ================") if verbose else None
    authenticator.receiveAckFromServer(pck_to_authenticator, verbose)
    msg = authenticator.prepareAckForUser(user.getPublicKey(), verbose)

    print(f"\n================ Fase ricezione ACK dell'Utente \"{user.name}\" ================") if verbose else None
    user.receiveAckFromAuthenticator(msg, verbose)



def singleUserIndividualVerification(user, authenticator, verbose: bool = True):
    """ Simula la fase di verifica individuale del voto di un singolo utente """

    print(f"\n\nStampa completa della fase di verifica individuale del voto per l'utente \"{user.name}\"") if verbose else print(f"\n\nStampa sintetica della fase di verifica individuale del voto per l'utente \"{user.name}\"")
    print(f"===================================================== Fase Verifica individuale del voto \"{user.name}\" ==========================================================")
    C_verify:list[bytes] = user.createCverify(verbose)
    C_response:list[bytes] = authenticator.receiveCverify(C_verify, verbose)
    user.finalizeIndividualVerification(C_response, verbose)