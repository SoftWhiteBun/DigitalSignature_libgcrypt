#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <gcrypt.h>
#include <iostream>

using namespace std;

#define BUFFER_SIZE 4096
enum EERORRS {
    CREATE_SEXPR_ERROR = 1,
    CREATE_KEY_ERROR,
    PRIVATE_KEY_MISSING,
    PUBLIC_KEY_MISSING,
    OPEN_FILE_ERROR,
    SIGNING_ERROR,
    ALLOCATE_ERROR,
    INVALID_PARAMETRS_ERROR
};

static void show_sexp (gcry_sexp_t a, FILE* SignFile)
{
  char *buf;
  size_t size;
  size = gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  buf = (char*)gcry_xmalloc (size);
  gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, buf, size);
  fprintf (SignFile, "%.*s", (int)size, buf);
  gcry_free (buf);
}

std::pair<gcry_sexp_t, gcry_sexp_t> KeyPairGenerate(char* argv[]) {
    pair <gcry_sexp_t, gcry_sexp_t> keyPair;
    gpg_error_t errorCode;
    gcry_sexp_t keySpec;
    gcry_sexp_t keyPairSexp;

    errorCode = gcry_sexp_build(&keySpec, NULL, "(genkey (dsa (nbits 4:1024)))");
    if (errorCode) {
         fprintf(stdout, "creating S-expression failed: %s\n", gcry_strerror (errorCode));
        exit(CREATE_SEXPR_ERROR);
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

void DigitalSignatureGenerate(char* argv[], gcry_sexp_t secretKey) {
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

    //--------------- ХЕШИРОВАНИЕ

    unsigned char * hash;
    gcry_sexp_t data;

    gcry_md_hd_t hd;
    gcry_md_open(&hd, GCRY_MD_SHA256, 0);

    unsigned char buffer[BUFFER_SIZE] = "";
    size_t nread;
    while ((nread = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        gcry_md_write(hd, buffer, nread);
    }

    hash = gcry_md_read(hd, GCRY_MD_SHA256);
    fprintf(stdout, "\nHash: ");
    for (int i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_SHA256); i++) {
        fprintf(stdout, "%c", hash[i]);
        fflush(stdout);
    }

    fprintf(stdout, "\n");

    gcry_sexp_build(&data, NULL, "(data (flags raw) (value %s))", hash);

    //---------------- ЭЦП

    errorCode = gcry_pk_sign(&DigitalSignature, data, secretKey);
    if (errorCode) {
        fprintf(stdout, "Signing faild: %s\n", gcry_strerror(errorCode));
        exit(SIGNING_ERROR);
    }
    cout << endl;
    show_sexp(DigitalSignature, stdout);
    cout << endl;
    show_sexp(DigitalSignature, SignFile);

    fclose(file);
    fclose(SignFile);
    gcry_md_close(hd);
}

void DigitalSignatureVerification(char* argv[], gcry_sexp_t publicKey) {
    gpg_error_t errorCode;
    gcry_sexp_t signature;

    FILE *file = fopen(argv[1], "rb");
    if (file == NULL) {
        printf("Error opening file %s\n", argv[1]);
        exit(OPEN_FILE_ERROR);
    }

    FILE *SignFile = fopen(argv[2], "r");
    if (SignFile == NULL) {
        printf("Error opening file %s\n", argv[2]);
        exit(OPEN_FILE_ERROR);
    }

    //---------------- ЧТЕНИЕ СИГНАТУРЫ ИЗ ФАЙЛА

    fseek( SignFile, 0, SEEK_END );
    long file_size = ftell( SignFile );
    char * buffer = (char*) malloc( file_size );
    if( !buffer ) {
        fclose( SignFile );
        fputs( "Could not allocate memory for file buffer. File could be empty or too large.", stderr );
        exit(ALLOCATE_ERROR);
    }
    fseek ( SignFile , 0, SEEK_SET );
    fread( buffer, 1, file_size, SignFile );

    errorCode = gcry_sexp_new(&signature, buffer, strlen(buffer), 0);
    if (errorCode) {
        fprintf(stdout, "creating S-expression failed: %s\n", gcry_strerror (errorCode));
        exit(CREATE_SEXPR_ERROR);
    }

    //-------------- НОВЫЙ ХЕШ

    gcry_md_hd_t new_hd;
    gcry_md_open(&new_hd, GCRY_MD_SHA256, 0);

    unsigned char new_buffer[BUFFER_SIZE]="";
    size_t new_nread;

    while ((new_nread = fread(new_buffer, 1, sizeof(new_buffer), file)) > 0) {
        gcry_md_write(new_hd, new_buffer, new_nread);
    }

    unsigned char * new_hash = gcry_md_read(new_hd, GCRY_MD_SHA256);
    fprintf(stdout, "\nHash: ");
    for (int i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_SHA256); i++) {
        fprintf(stdout, "%c", new_hash[i]);
    }
    fflush(stdout);
    fprintf(stdout, "\n");

    gcry_sexp_t new_data;
    gcry_sexp_build(&new_data, NULL, "(data (flags raw) (value %s))", new_hash);

    //--------------- ПРОВЕРКА

    errorCode = gcry_pk_verify(signature, new_data, publicKey);
    if (errorCode) {
        fprintf(stdout, "verify faild: %s\n\n", gcry_strerror(errorCode));
        fprintf(stdout, (const char*)new_buffer);
    } else fprintf(stdout, "SUCCESS\n");

    gcry_md_close(new_hd);
    fclose(file);
    fclose(SignFile);

}

int main(int argc, char* argv[]) {

    if (argc != 3) {
        printf("Usage: %s <filename>\n", argv[0]);
        exit(INVALID_PARAMETRS_ERROR);
    }

    bool UExit = false;
    char UMenu;

    //--------------- ГЕНЕРАЦИЯ КЛЮЧА

    auto [secretKey, publicKey] = KeyPairGenerate(argv); // генерация ключа должна быть в генерации ЭЦП + запись в файл публичной части

    // ------------------------ МЕНЮ -------------------------------

        while (!UExit) {
            cout << "Menu: " << endl;
            cout << "Print char to:" << endl;
            cout << "g - to generate EDS" << endl;
            cout << "v - to verify EDS" << endl; // чтение публичного ключа из файла
            cout << "e - to exit" << endl;

            cin >> UMenu;

            if (UMenu == 'g') {
                DigitalSignatureGenerate(argv, secretKey);
            }

            else if (UMenu == 'v') {
                DigitalSignatureVerification(argv, publicKey);
            }

            else if (UMenu == 'e')
                UExit = true;
        }

        return 0;
}
