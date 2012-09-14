/*
 * Mcrypt encryption / decryption sample.
 *
 * The primary purpose of this sample is to demonstrate how to call the
 * mcrypt C APIs to produce cookie data usable by mod_auth_cookie.
 * There is already a much more functional shell commandline interface
 * to mcrypt available; see `man 1 mcrypt`.
 *
 * Note that this sample does not do the mandetory base64 encoding necessary
 * for creating a valid cookie.  str_base64_encode from libcgi/cgi.h may be
 * used for this purpose.
 *
 * Encrypt a string, then decrypt it again:
 *
 *   echo "secret data" | ./crypt_sample --iv | ./crypt_sample --decrypt
 *
 * To create a base64-encoded string suitable for use by mod_auth_cookie:
 *
 *   echo "user@mail.com     user:password" | ./crypt_sample --iv | base64
 *
 *   (n.b. Type control-V [TAB] to insert a literal tab into commandline)
 *
 * To decrypt a base64-encoded cookie used by mod_auth_cookie:
 *
 *   echo "d594mC29k1oBAAHa1uYoK/SwefGbOBR00OHnOCTIwUBb7tqX3bE+Fg9/mr4LjilS" | base64 -d | ./crypt_sample --decrypt
 *
 * Note:  to specify a different encryption key, use:
 *
 *  ./crypt_sample --key mybettersecretencryptionkey12345
 *
 * Prior to building:
 *
 * sudo apt-get install libmcrypt-dev
 * sudo apt-get install libcgi-dev
 */

#include <libcgi/cgi.h>
#include <mcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Options.
 */
#define OPT_DECRYPT   (1 << 0)  // --decrypt
#define OPT_IV        (1 << 1)  // --iv

/*
 * Put random data in IV. Note these are not real random data,
 * consider using /dev/random or /dev/urandom.
 */
void crypt_sample_create_iv(char* iv, int iv_size) {
  int i;
  srand(time(0));
  for (i=0; i < iv_size; i++) {
    iv[i]=rand();
  }
}

/*
 * Encrypt or decrypt some data.  Read input from stdin; write to stdout.
 *
 * Parameters:
 *
 * algorithm:  Use MCRYPT_RIJNDAEL_128 for use with auth_cookie_sso
 *
 * mode:  Use MCRYPT_CBC for use with auth_cookie_sso
 *
 * key:  Use the value from AuthCookieEncrypt here
 *
 * options: Binary-OR desired options together:
 *        OPT_DECRYPT - decrypt input rather than decrypting it.
 *        OPT_IV - in encryption mode, print out the generated iv in the result
 *
 * iv:  Optional.  A new random iv will be generated if this is NULL.
 */
int crypt_sample(char* algorithm, char* mode, char* key, char* iv, int options) {
  MCRYPT td = mcrypt_module_open(algorithm, NULL, mode, NULL);
  int block_size = mcrypt_enc_get_block_size(td);
  int iv_size = mcrypt_enc_get_iv_size(td);
  int key_size = strlen(key);
  char *block_buffer = malloc(block_size);

  if (iv == NULL) {
    iv=malloc(iv_size);
    // In decrypt mode, we expect that the iv is always at the head of
    // the input stream.
    if (options & OPT_DECRYPT) {
      fread(iv, 1, iv_size, stdin);
    }
    else {
      crypt_sample_create_iv(iv, iv_size);
    }
  }

  // In encryption mode, we will write the iv to the beginning of
  // the output stream if --iv is specified
  if ((!(options & OPT_DECRYPT)) && (options & OPT_IV)) {
    fwrite(iv, 1, iv_size, stdout);
  }

  mcrypt_generic_init(td, key, key_size, iv);
  /* Encryption in CBC is performed in blocks */
  bzero(block_buffer, block_size);
  while( fread(block_buffer, 1, block_size, stdin) > 0 ) {
    if (options & OPT_DECRYPT) {
      mdecrypt_generic (td, block_buffer, block_size);
    }
    else {
      mcrypt_generic (td, block_buffer, block_size);
    }
    fwrite ( block_buffer, 1, block_size, stdout);
    bzero(block_buffer, block_size);
  }
  /* deinitialize the encryption thread */
  mcrypt_generic_deinit (td);
  /* Unload the loaded module */
  mcrypt_module_close(td);
  return 0;
}

int crypt_sample_hex2digit(char hex) {
  if ((hex >= '0') && (hex <= '9')) {
    return hex - '0';
  }
  if ((hex >= 'a') && (hex <= 'f')) {
    return 10 + (hex - 'a');
  }
  if ((hex >= 'A') && (hex <= 'F')) {
    return 10 + (hex - 'A');
  }
  return 0;
}

int crypt_sample_hex2bin(char* bin, const char* hex) {
  int length = 0;
  int i = 0;
  while (hex[i] != 0) {
    int value = 0x10 * crypt_sample_hex2digit(hex[i]);
    ++i;
    if (hex[i] != 0) {
      value += crypt_sample_hex2digit(hex[i]);
      ++i;
    }
    bin[length] = value;
    ++length;
  }
  return length;
}

int main(int argc, char **argv) {
  char *algorithm = MCRYPT_RIJNDAEL_128;
  char *mode = MCRYPT_CBC;
  char *key = "secretsecretencryptionkey1234567";
  char *iv = NULL;
  int options = 0;
  int i = 1;

  while (i < argc) {
    if (strcmp(argv[i], "--key") == 0) {
      ++i;
      key = argv[i];
    }
    else if (strcmp(argv[i], "--algorithm") == 0) {
      ++i;
      algorithm = argv[i];
    }
    else if (strcmp(argv[i], "--mode") == 0) {
      ++i;
      mode = argv[i];
    }
    else if (strcmp(argv[i], "--iv") == 0) {
      options |= OPT_IV;
    }
    else if (strcmp(argv[i], "--iv-hex") == 0) {
      ++i;
      iv = malloc(strlen(argv[i]));
      bzero(iv, strlen(argv[i]));
      int iv_size = crypt_sample_hex2bin(iv, argv[i]);
    }
    else if (strcmp(argv[i], "--decrypt") == 0) {
      options |= OPT_DECRYPT;
    }
    else {
      printf("Unknown option %s\n", argv[i]);
      exit(1);
    }
    ++i;
  }

  return crypt_sample(algorithm, mode, key, iv, options);
}
