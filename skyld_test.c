#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winscard.h>

#define QUANTIFICATION_FLOAT16 0
#define QUANTIFICATION_FLOAT32 1

SCARDCONTEXT ctx;
SCARDHANDLE card;
DWORD active_proto;
LONG res;

BYTE recv_buf[11000];
DWORD recv_len;

void print_hex(const char *label, const unsigned char *buf, DWORD len) {
    printf("%s: ", label);
    for (DWORD i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

const SCARD_IO_REQUEST *getIOSend_NK3() {
    return (active_proto == SCARD_PROTOCOL_T1) ? SCARD_PCI_T1 : SCARD_PCI_T0;
}

void init_NK3() {
    // 1. Initialiser le contexte PC/SC
    res = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
    if (res != SCARD_S_SUCCESS) {
        fprintf(stderr, "Échec SCardEstablishContext: 0x%08lX\n", res);
        return;
    }

    // 2. Détecter le lecteur virtuel Nitrokey
    DWORD readers_len = 0;
    SCardListReaders(ctx, NULL, NULL, &readers_len);
    char *readers = malloc(readers_len);
    SCardListReaders(ctx, NULL, readers, &readers_len);

    char *selected_reader = NULL;
    char *curr = readers;
    while (*curr != '\0') {
        printf("Lecteur disponible : %s\n", curr);
        if (strstr(curr, "Nitrokey 3") != NULL) {
            selected_reader = curr;
            break;
        }
        curr += strlen(curr) + 1;
    }
    printf("Lecteur détecté : %s\n", selected_reader);

    // 3. Se connecter à la carte à puce virtuelle
    res = SCardConnect(ctx, selected_reader, SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T1, &card, &active_proto);
    if (res != SCARD_S_SUCCESS) {
        fprintf(stderr, "Échec SCardConnect: 0x%08lX\n", res);
        free(readers);
        SCardReleaseContext(ctx);
        return;
    }

    free(readers);
}

int load_KN3() {
    // Sélectionne skyldApp
    // 4. Commande 1: SELECT AID (0xF0, 0x53, 0x6B, 0x79, 0x6C, 0x64 -> "Skyld")
    // CLA=00, INS=A4 (SELECT), P1=04 (By AID), P2=00, Lc=06, Data=AID
    BYTE select_apdu[] = {0x00, 0xA4, 0x04, 0x00, 0x06, 0xF0, 0x53, 0x6B, 0x79, 0x6C, 0x64};
    recv_len = sizeof(recv_buf);
    res = SCardTransmit(card, getIOSend_NK3(), select_apdu, sizeof(select_apdu), NULL, recv_buf, &recv_len);
    print_hex("Réponse SELECT AID", recv_buf, recv_len);

    // 5. Commande 2: INS 0x01 (Unwrap Seed)
    // CLA=00, INS=01, P1=QUANTIFICATION_FLOAT32, P2=00, Lc=20 (32 octets de test), Data...
    BYTE unwrap_apdu[5 + 52] = {0x00, 0x01, QUANTIFICATION_FLOAT32, 0x00, 52};
    memset(&unwrap_apdu[5], 0xAA, 52); // Seed de test 0xAA...
    recv_len = sizeof(recv_buf);
    res = SCardTransmit(card, getIOSend_NK3(), unwrap_apdu, sizeof(unwrap_apdu), NULL, recv_buf, &recv_len);
    print_hex("Réponse UNWRAP", recv_buf, recv_len);

    return 0;
}

void deriveSessionKey_NK3() {
    // 6. Commande 3: INS 0x02 (Derive Key)
    // CLA=00, INS=02, P1=00, P2=00, Lc=04 (paramètres), Data={1, 2, 3, 4}, Le=00
    BYTE derive_apdu[] = {0x00, 0x02, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x00}; // P1 à 0 pour l'indice 0
    recv_len = sizeof(recv_buf);
    res = SCardTransmit(card, getIOSend_NK3(), derive_apdu, sizeof(derive_apdu), NULL, recv_buf, &recv_len);
    print_hex("Réponse DERIVE", recv_buf, recv_len);
}

void clear_NK3() {
    SCardDisconnect(card, SCARD_RESET_CARD); // Clean RAM
    SCardReleaseContext(ctx);
}

int main(void) {
    init_NK3();

    load_KN3();

    deriveSessionKey_NK3();

    clear_NK3();

    return 0;
}
