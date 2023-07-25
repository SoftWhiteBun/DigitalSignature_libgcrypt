#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <gcrypt.h>
#include <iostream>

using namespace std;

#define BUFFER_SIZE 4096
enum EERORRS {
    CREATE_SEXP_ERROR = 1,
    CREATE_KEY_ERROR,
    PRIVATE_KEY_MISSING,
    PUBLIC_KEY_MISSING,
    OPEN_FILE_ERROR,
    SIGNING_ERROR,
    ALLOCATE_ERROR,
    INVALID_PARAMETRS_ERROR
};

static void show_sexp (gcry_sexp_t sexp, FILE* file) {
  char *buf;
  size_t size;
  size = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  buf = (char*)gcry_xmalloc (size);
  gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, buf, size);
  fprintf (file, "%.*s", (int)size, buf);
  gcry_free (buf);
}

gcry_sexp_t readSexpFile(FILE* file) {
    gcry_sexp_t sexp;
    gpg_error_t errorCode;

    fseek( file, 0, SEEK_END );
    long file_size = ftell( file );
    char * buffer = (char*) malloc( file_size );
    if( !buffer ) {
        fclose( file );
        fputs( "Could not allocate memory for file buffer. File could be empty or too large.", stderr );
        exit(ALLOCATE_ERROR);
    }
    fseek ( file , 0, SEEK_SET );
    fread( buffer, 1, file_size, file );

    errorCode = gcry_sexp_new(&sexp, buffer, strlen(buffer), 0);
    if (errorCode) {
        fprintf(stdout, "Creating S-expression failed: %s\n", gcry_strerror (errorCode));
        exit(CREATE_SEXP_ERROR);
    }
    free(buffer);

    return sexp;
}

std::pair<gcry_sexp_t, gcry_sexp_t> KeyPairGenerate(char* argv[]) {
    pair <gcry_sexp_t, gcry_sexp_t> keyPair;
    gpg_error_t errorCode;
    gcry_sexp_t keySpec;
    gcry_sexp_t keyPairSexp;

    errorCode = gcry_sexp_build(&keySpec, NULL, "(genkey (dsa (nbits 4:1024)))");
    if (errorCode) {
         fprintf(stdout, "creating S-expression failed: %s\n", gcry_strerror (errorCode));
        exit(CREATE_SEXP_ERROR);
    }

    errorCode = gcry_pk_genkey (&keyPairSexp, keySpec);
    if (errorCode) {
        fprintf(stdout, "creating %s  key failed: %s\n", argv[1], gcry_strerror (errorCode));
        exit(CREATE_KEY_ERROR);
    }

    // Закрытый ключ
    keyPair.first = gcry_sexp_find_token(keyPairSexp, "private-key", 0);
    if(!keyPair.first) {
        fprintf(stdout, "private part missing in key\n");
        exit(PRIVATE_KEY_MISSING);
    }

    // Сохраняем публичный ключ
    keyPair.second = gcry_sexp_find_token (keyPairSexp, "public-key", 0);
    if (! keyPair.second) {
        fprintf(stderr, "public part missing in key\n");
        exit(PUBLIC_KEY_MISSING);
    }

    return keyPair;
}

gcry_sexp_t HashGenerate(FILE* file) {
    unsigned char * data;
    gcry_sexp_t hash;

    gcry_md_hd_t hd;
    gcry_md_open(&hd, GCRY_MD_SHA256, 0);

    unsigned char buffer[BUFFER_SIZE] = "";
    size_t nread;
    while ((nread = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        gcry_md_write(hd, buffer, nread);
    }

    data = gcry_md_read(hd, GCRY_MD_SHA256);
    fprintf(stdout, "\nHash: ");
    for (int i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_SHA256); i++) {
        fprintf(stdout, "%c", data[i]);
        fflush(stdout);
    }

    fprintf(stdout, "\n");

    gcry_sexp_build(&hash, NULL, "(data (flags raw) (value %s))", data);

    gcry_md_close(hd);
<<<<<<< HEAD

    return hash;
}

void DigitalSignatureGenerate(char* argv[]) {
    gcry_sexp_t DigitalSignature;
    gpg_error_t errorCode;
    gcry_sexp_t hash;

    FILE *DataFile = fopen(argv[1], "rb");
    if (DataFile == NULL) {
        printf("Error opening file %s\n", argv[1]);
        exit(OPEN_FILE_ERROR);
    }

    FILE *SignFile = fopen(argv[2], "w");
    if (SignFile == NULL) {
        printf("Error opening file %s\n", argv[2]);
        exit(OPEN_FILE_ERROR);
    }

    FILE *PubKeyFile = fopen(argv[3], "w");
    if (PubKeyFile == NULL) {
        printf("Error opening file %s\n", argv[3]);
        exit(OPEN_FILE_ERROR);
    }

    auto [secretKey, publicKey] = KeyPairGenerate(argv); // генерация ключей
    show_sexp(publicKey, PubKeyFile);

    hash = HashGenerate(DataFile); // хеширование

    errorCode = gcry_pk_sign(&DigitalSignature, hash, secretKey); // генерация ЭЦП
=======

    return hash;
}

void DigitalSignatureGenerate(char* argv[]) {
    gcry_sexp_t DigitalSignature;
    gpg_error_t errorCode;

    FILE *file = fopen(argv[1], "rb");
    if (file == NULL) {
        printf("Error opening file %s\n", argv[1]);
        exit(OPEN_FILE_ERROR);
    }

    FILE *SignFile = fopen(argv[2], "w");
    if (SignFile == NULL) {
        printf("Error opening file %s\n", argv[2]);
        exit(OPEN_FILE_ERROR);
    }

    FILE *PubKeyFile = fopen(argv[3], "w");
    if (PubKeyFile == NULL) {
        printf("Error opening file %s\n", argv[3]);
        exit(OPEN_FILE_ERROR);
    }

    //-------------- ГЕНЕРАЦИЯ КЛЮЧЕЙ

    auto [secretKey, publicKey] = KeyPairGenerate(argv);
    show_sexp(publicKey, PubKeyFile);

    //--------------- ХЕШИРОВАНИЕ

    gcry_sexp_t hash;
    hash = HashGenerate(file);
    //---------------- ЭЦП

    errorCode = gcry_pk_sign(&DigitalSignature, hash, secretKey);
>>>>>>> 467061a8ed81b693575dec046885ebd10e54cdf6
    if (errorCode) {
        fprintf(stdout, "Signing faild: %s\n", gcry_strerror(errorCode));
        exit(SIGNING_ERROR);
    }

    show_sexp(DigitalSignature, SignFile);

    cout << "Digital signature generated success" << endl;

    fclose(DataFile);
    fclose(SignFile);
    fclose(PubKeyFile);
}

void DigitalSignatureVerification(char* argv[]) {
    gpg_error_t errorCode;
    gcry_sexp_t publicKey;
    gcry_sexp_t hash;
    gcry_sexp_t signature;
    gcry_sexp_t publicKey;

    FILE *DataFile = fopen(argv[1], "rb");
    if (DataFile == NULL) {
        printf("Error opening file %s\n", argv[1]);
        exit(OPEN_FILE_ERROR);
    }

    FILE *SignFile = fopen(argv[2], "r");
    if (SignFile == NULL) {
        printf("Error opening file %s\n", argv[2]);
        exit(OPEN_FILE_ERROR);
    }

    FILE *PubKeyFile = fopen(argv[3], "r");
    if (PubKeyFile == NULL) {
        printf("Error opening file %s\n", argv[3]);
        exit(OPEN_FILE_ERROR);
    }
<<<<<<< HEAD
=======

    signature = readSexpFile(SignFile);
    publicKey = readSexpFile(PubKeyFile);
>>>>>>> 467061a8ed81b693575dec046885ebd10e54cdf6

    signature = readSexpFile(SignFile);
    publicKey = readSexpFile(PubKeyFile);

<<<<<<< HEAD
    hash = HashGenerate(DataFile); // хеширование

    errorCode = gcry_pk_verify(signature, hash, publicKey); // верификация
    if (errorCode) {
        fprintf(stdout, "verify faild: %s\n\n", gcry_strerror(errorCode));
    } else fprintf(stdout, "VERIFY SUCCESS\n");

    fclose(DataFile);
=======
//    gcry_md_hd_t new_hd;
//    gcry_md_open(&new_hd, GCRY_MD_SHA256, 0);

//    unsigned char new_buffer[BUFFER_SIZE]="";
//    size_t new_nread;

//    while ((new_nread = fread(new_buffer, 1, sizeof(new_buffer), file)) > 0) {
//        gcry_md_write(new_hd, new_buffer, new_nread);
//    }

//    unsigned char * new_hash = gcry_md_read(new_hd, GCRY_MD_SHA256);
//    fprintf(stdout, "\nHash: ");
//    for (int i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_SHA256); i++) {
//        fprintf(stdout, "%c", new_hash[i]);
//    }
//    fflush(stdout);
//    fprintf(stdout, "\n");

//    gcry_sexp_t new_data;
//    gcry_sexp_build(&new_data, NULL, "(data (flags raw) (value %s))", new_hash);

    gcry_sexp_t hash;
    hash = HashGenerate(file);

    //--------------- ПРОВЕРКА

    errorCode = gcry_pk_verify(signature, hash, publicKey);
    if (errorCode) {
        fprintf(stdout, "verify faild: %s\n\n", gcry_strerror(errorCode));
        //fprintf(stdout, (const char*)new_buffer);
    } else fprintf(stdout, "SUCCESS\n");

    //gcry_md_close(new_hd);
    fclose(file);
>>>>>>> 467061a8ed81b693575dec046885ebd10e54cdf6
    fclose(SignFile);
    fclose(PubKeyFile);

}

int main(int argc, char* argv[]) {

    if (argc != 4) {
        printf("Usage: %s <filename>\n", argv[0]);
        exit(INVALID_PARAMETRS_ERROR);
    }

    bool UExit = false;
    char UMenu;
        while (!UExit) {
            cout << "Menu: " << endl;
            cout << "Print char to:" << endl;
            cout << "g - to generate EDS" << endl;
            cout << "v - to verify EDS" << endl;
            cout << "e - to exit" << endl;

            cin >> UMenu;

            if (UMenu == 'g') {
                DigitalSignatureGenerate(argv);
            }

            else if (UMenu == 'v') {
                DigitalSignatureVerification(argv);
            }

            else if (UMenu == 'e')
                UExit = true;
        }

        return 0;
}
