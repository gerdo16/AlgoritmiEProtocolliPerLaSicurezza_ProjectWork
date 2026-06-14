RESET_COLOR = "\033[0m"

#giallo
CA_COLOR = "\033[93m"
PRINT_START_CA = f"{CA_COLOR}[CertificationAuthority]{RESET_COLOR}"

#verde
AUTHENTICATOR_COLOR = "\033[92m"
PRINT_START_AUTHENTICATOR = f"{AUTHENTICATOR_COLOR}[Authenticator]{RESET_COLOR}"

#rosso
SERVER_COLOR = "\033[91m"
PRINT_START_SERVER = f"{SERVER_COLOR}[Server]{RESET_COLOR}"

#blu
USER_COLOR = "\033[94m"
PRINT_START_USER = f"{USER_COLOR}[User]{RESET_COLOR}"


if __name__ == "__main__":
    print(PRINT_START_CA+" questo è un messaggio di test per la CA")
    print(PRINT_START_AUTHENTICATOR+" questo è un messaggio di test per l'Authenticator")
    print(PRINT_START_SERVER+" questo è un messaggio di test per il Server")
    print(PRINT_START_USER+" questo è un messaggio di test per l'User")