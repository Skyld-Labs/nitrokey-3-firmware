#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winscard.h>

#include <stdbool.h>
#include <stdint.h>

#include "gift128.h"

#define QUANTIFICATION_FLOAT16 0
#define QUANTIFICATION_FLOAT32 1

#define HASH_LEN 32
#define KEY_LEN 20 // ou n'importe quelle autre taille
#define PAYLOAD_LEN (HASH_LEN + KEY_LEN)

int getMetadataVersion(unsigned char *metadataBuff);
void getKeyFileNames(uint8_t *metadataBuffWithoutHeader, size_t buffSize, bool V3);
void convertCofbToAES(const char *filename);
void decipherCofb(unsigned char **encryptedFileBuff, long fileSize);

uint8_t masterKey[16];

char **keyFileNames;
int modelCount = 0;

SCARDCONTEXT ctx;
SCARDHANDLE card;
DWORD active_proto;
LONG res;

BYTE recv_buf[11000];
DWORD recv_len;

int getMetadataVersion(unsigned char *metadataBuff) {
  if (*((int *)metadataBuff) != 0) {
    return 0;
  } else {
    return *((int *)&metadataBuff[4]);
  }
}

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

    // Sélectionne skyldApp
    // 4. Commande 1: SELECT AID (0xF0, 0x53, 0x6B, 0x79, 0x6C, 0x64 -> "Skyld")
    // CLA=00, INS=A4 (SELECT), P1=04 (By AID), P2=00, Lc=06, Data=AID
    BYTE select_apdu[] = {0x00, 0xA4, 0x04, 0x00, 0x06, 0xF0, 0x53, 0x6B, 0x79, 0x6C, 0x64};
    recv_len = sizeof(recv_buf);
    res = SCardTransmit(card, getIOSend_NK3(), select_apdu, sizeof(select_apdu), NULL, recv_buf, &recv_len);
    print_hex("Réponse SELECT AID", recv_buf, recv_len);

    free(readers);
}

void getKeyFileNames(uint8_t *metadataBuffWithoutHeader, size_t buffSize, bool V3) {
    size_t cursorPos = 0;

    const uint8_t sizeLine = V3 ? 43 : 42;

    while (cursorPos < buffSize && cursorPos + sizeLine <= buffSize) {
        modelCount++;
        keyFileNames = realloc(keyFileNames, modelCount * sizeof(char *));

        cursorPos += 40;

        size_t keyFileNameLength = 0;
        while (metadataBuffWithoutHeader[cursorPos + keyFileNameLength] != '\0' && cursorPos + keyFileNameLength < buffSize) {
            keyFileNameLength++;
        }
    
        keyFileNames[modelCount - 1] = malloc(keyFileNameLength + 1);
        if (keyFileNames[modelCount - 1] == NULL) {
            printf("Allocation failed");
            exit(1);
        }
    
        strncpy(keyFileNames[modelCount - 1],
                    (const char *)&metadataBuffWithoutHeader[cursorPos],
                    keyFileNameLength);
        keyFileNames[modelCount - 1][keyFileNameLength] = '\0';
        cursorPos += keyFileNameLength + 1;

        if (V3) {
            cursorPos += 1;
        }
    }
}

void convertCofbToAES(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf("Warning : opening \"%s\" in read mode failed\n", filename);
        return;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0) {
        printf("Error : empty file\n");
        fclose(f);
        exit(1);
    }

    uint8_t *plaintext = malloc(file_size);
    uint8_t *ciphertext = malloc(file_size);
    
    if (!plaintext || !ciphertext) {
        printf("Error : malloc failed\n");
        if(plaintext) free(plaintext);
        if(ciphertext) free(ciphertext);
        fclose(f);
        return;
    }

    fread(plaintext, 1, file_size, f);
    fclose(f);

    decipherCofb(&plaintext, file_size);

    // Read all key file names
    if (strcmp(filename, "skrpl") == 0) {
        switch (getMetadataVersion(plaintext)) {
            case 1:
                getKeyFileNames(plaintext + 8, file_size - 8, false);
                break;
            case 2:
                getKeyFileNames(plaintext + 12, file_size - 12, false);
                break;
            case 3:
                getKeyFileNames(plaintext + 12, file_size - 12, true);
                break;
            default:
                printf("Error : unsupported skrpl version\n");
                exit(1);
        }
    }

    // Call WRAP on Nitrokey 3
    BYTE wrap_apdu[5 + PAYLOAD_LEN + 1];
    wrap_apdu[0] = 0x00;
    wrap_apdu[1] = 0x01; // INS 0x01 = WRAP
    wrap_apdu[2] = 0x00;
    wrap_apdu[3] = 0x00;
    wrap_apdu[4] = PAYLOAD_LEN;

    // 1. Les 32 premiers octets : le hash
    memset(&wrap_apdu[5], 0xBB, HASH_LEN); // TODO  : replace with SAH256 derived from masterKey

    // 2. De l'octet 32 jusqu'à la fin : la seed
    memcpy(&wrap_apdu[5 + HASH_LEN], plaintext, KEY_LEN);

    wrap_apdu[5 + PAYLOAD_LEN] = 0x00; // Tell to receive data

    recv_len = sizeof(recv_buf);
    res = SCardTransmit(card, getIOSend_NK3(), wrap_apdu, sizeof(wrap_apdu), NULL, recv_buf, &recv_len);
    print_hex("Réponse WRAP", recv_buf, recv_len);

    f = fopen(filename, "wb");
    if (!f) {
        perror("Error : file can't be open in write mode\n");
        return;
    }

    fwrite(recv_buf, recv_len - 2, 1, f);

    fclose(f);

    printf("Success : '%s' has been encrypted\n", filename);
}

void decipherCofb(unsigned char **encryptedFileBuff, long fileSize) {
    // The file contains the nonce at its start
    unsigned char *nonce = *encryptedFileBuff;
    unsigned char *cipher = *encryptedFileBuff + NONCEBYTES;

    unsigned cipherSize = fileSize - NONCEBYTES;
    unsigned messageSize = cipherSize - TAGBYTES;
    unsigned char* buffer = malloc(messageSize);

    int status = cofb_crypt(buffer, masterKey, nonce, NULL, 0, cipher,
                            cipherSize, COFB_DECRYPT);

    free(*encryptedFileBuff);

    if (status) {
      printf("Error: Decrypt returned = %d", status);
      free(buffer);
      exit(1);
    }

    *encryptedFileBuff = buffer;
}

void provide_NK3() {
    convertCofbToAES("skrpl");
    for (int i = 0; i < modelCount; i++) {
        convertCofbToAES(keyFileNames[i]);
    }
}



int load_KN3() {
    // 5. Commande 2: INS 0x02 (Unwrap Seed)
    // CLA=00, INS=01, P1=QUANTIFICATION_FLOAT32, P2=00, Lc=20 (32 octets de test), Data...

    BYTE unwrap_apdu[5 + PAYLOAD_LEN];
    unwrap_apdu[0] = 0x00;
    unwrap_apdu[1] = 0x02;
    unwrap_apdu[2] = QUANTIFICATION_FLOAT32;
    unwrap_apdu[3] = 0x01; // 1 = it's a key, 0 other (mainly skrpl)
    unwrap_apdu[4] = PAYLOAD_LEN;

    // 1. Les 32 premiers octets : le hash
    memset(&unwrap_apdu[5], 0xBB, HASH_LEN);

    // 2. De l'octet 32 jusqu'à la fin : la seed
    memset(&unwrap_apdu[5 + HASH_LEN], 0xAA, KEY_LEN);

    recv_len = sizeof(recv_buf);
    res = SCardTransmit(card, getIOSend_NK3(), unwrap_apdu, sizeof(unwrap_apdu), NULL, recv_buf, &recv_len);
    print_hex("Réponse UNWRAP", recv_buf, recv_len);

    return 0;
}

void deriveSessionKey_NK3() {
    // 6. Commande 3: INS 0x03 (Derive Key)
    // CLA=00, INS=02, P1=00, P2=00, Lc=04 (paramètres), Data={1, 2, 3, 4}, Le=00
    BYTE derive_apdu[] = {0x00, 0x03, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x00}; // P1 à 0 pour l'indice 0
    recv_len = sizeof(recv_buf);
    res = SCardTransmit(card, getIOSend_NK3(), derive_apdu, sizeof(derive_apdu), NULL, recv_buf, &recv_len);
    print_hex("Réponse DERIVE", recv_buf, recv_len);
}

void clear_NK3() {
    SCardDisconnect(card, SCARD_RESET_CARD); // Clean RAM
    SCardReleaseContext(ctx);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Please specify the master key.\n");
        return 0;
    }

    if (strlen(argv[1]) != sizeof(masterKey) * 2) {
        printf("Master key has a wrong size.\n");
        return -1;
    }

    for (size_t i = 0; i < sizeof(masterKey); i++) {
        unsigned int byte;

        if (sscanf(argv[1] + (i * 2), "%2x", &byte) != 1) {
            return -1;
        }

        masterKey[i] = (uint8_t)byte;
    }

    init_NK3();

    provide_NK3();

    //load_KN3();

    //deriveSessionKey_NK3();

    clear_NK3();

    return 0;
}
