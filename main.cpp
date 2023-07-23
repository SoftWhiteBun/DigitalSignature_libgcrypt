#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <gcrypt.h>
#include <iostream>

using namespace std;

#define BUFFER_SIZE 4096

/*Функция печати S-выражений*/
static void
show_sexp (const char *prefix, gcry_sexp_t a, FILE* SignFile)
{
  char *buf;
  size_t size;
  if (prefix) fputs (prefix, SignFile);
  size = gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  buf = (char*)gcry_xmalloc (size);
  gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, buf, size);
  fprintf (SignFile, "%.*s", (int)size, buf);
  fprintf(SignFile, "\n");
  gcry_free (buf);
}

//struct SKeys {
//    gcry_sexp_t _publicKey;
//    gcry_sexp_t _secretKey;
//};

std::pair<gcry_sexp_t, gcry_sexp_t> KeyPairGenerate(char* argv[]) {
    pair <gcry_sexp_t, gcry_sexp_t> keyPair;
    gpg_error_t errorCode;
    gcry_sexp_t keySpec;
    gcry_sexp_t keyPairSexp;

    errorCode = gcry_sexp_build (&keySpec, NULL, "(genkey (dsa (nbits 4:1024)))");
    if (errorCode) {
         fprintf(stdout, "creating S-expression failed: %s\n", gcry_strerror (errorCode));
        exit (1);
    }

    errorCode = gcry_pk_genkey (&keyPairSexp, keySpec);
    if (errorCode){
        fprintf(stdout, "creating %s  key failed: %s\n", argv[1], gcry_strerror (errorCode));
        exit(1);
    }

    // Закрытый ключ
    keyPair.first = gcry_sexp_find_token(keyPairSexp, "private-key", 0);
    if(!keyPair.first) {
        fprintf(stdout, "private part missing in key\n");
        exit(1);
    }

    // Сохраняем публичный ключ
    keyPair.second = gcry_sexp_find_token (keyPairSexp, "public-key", 0);
    if (! keyPair.second) {
        fprintf(stderr, "public part missing in key\n");
        exit(1);
    }

    return keyPair;
}

int main(int argc, char* argv[]) {

    bool UExit = false;
    char UMenu;

    if (argc != 3) {
        printf("Usage: %s <filename>\n", argv[0]);
        exit(1);
    }

    //--------------- ГЕНЕРАЦИЯ КЛЮЧА

    gpg_error_t err;
    gcry_sexp_t publicKey, secretKey;

    pair <gcry_sexp_t, gcry_sexp_t> keyPair = KeyPairGenerate(argv);
    secretKey = keyPair.first;
    publicKey = keyPair.second;


    //-------------------- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ

    gcry_sexp_t sig;

    // ------------------------ МЕНЮ -------------------------------

        while (!UExit) {
            cout << "Menu: " << endl;
            cout << "Print char to:" << endl;
            cout << "g - to generate EDS" << endl;
            cout << "v - to verify EDS" << endl;
            cout << "e - to exit" << endl;

            cin >> UMenu;

            if (UMenu == 'g') {

                FILE *file = fopen(argv[1], "rb");
                if (file == NULL) {
                    printf("Error opening file %s\n", argv[1]);
                    exit(1);
                }

                FILE *SignFile = fopen(argv[2], "w");
                if (SignFile == NULL) {
                    printf("Error opening file %s\n", argv[2]);
                    exit(1);
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

                err = gcry_pk_sign(&sig, data, secretKey);
                if (err) {
                    fprintf(stdout, "Signing faild: %s\n", gcry_strerror(err));
                    exit(1);
                }
                show_sexp("\n", sig, stdout);
                show_sexp("", sig, SignFile);

                fclose(file);
                fclose(SignFile);
                gcry_md_close(hd);

            } else

            if (UMenu == 'v') {

                FILE *file = fopen(argv[1], "rb");
                if (file == NULL) {
                    printf("Error opening file %s\n", argv[1]);
                    exit(1);
                }

                FILE *SignFile = fopen(argv[2], "r");
                if (SignFile == NULL) {
                    printf("Error opening file %s\n", argv[2]);
                    exit(1);
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

                err = gcry_pk_verify(sig, new_data, publicKey);
                if (err) {
                    fprintf(stdout, "verify faild: %s\n\n", gcry_strerror(err));
                    fprintf(stdout, (const char*)new_buffer);
                } else fprintf(stdout, "SUCCESS\n");

                gcry_md_close(new_hd);
                fclose(file);
                fclose(SignFile);

            } else

            if (UMenu == 'e') UExit = true;
        }

//--------------------------- КОНЕЦ

        return 0;

}
