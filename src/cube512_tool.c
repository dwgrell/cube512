#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <archive.h>
#include <archive_entry.h>
#include <lz4frame.h>
#include <glob.h>

#define BLOCK_BYTES 64
#define IV_SIZE 16

void init_lut(void);
void encrypt_block(const uint8_t plain[BLOCK_BYTES], const uint8_t key[BLOCK_BYTES], uint8_t cipher[BLOCK_BYTES]);
void decrypt_block(const uint8_t cipher[BLOCK_BYTES], const uint8_t key[BLOCK_BYTES], uint8_t plain[BLOCK_BYTES]);

static void derive_key(const void *data, size_t len, uint8_t key[BLOCK_BYTES]) {
    uint8_t hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, hash, 32);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    memcpy(key, hash, 32);
    memcpy(key + 32, hash, 32);
    EVP_MD_CTX_free(ctx);
}

static int read_key_from_file(const char *fname, uint8_t key[BLOCK_BYTES]) {
    FILE *f = fopen(fname, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *data = malloc(size);
    if (!data) { fclose(f); return 0; }
    fread(data, 1, size, f);
    fclose(f);
    derive_key(data, size, key);
    free(data);
    return 1;
}

static void pkcs7_pad(uint8_t *data, size_t *len, size_t block) {
    size_t pad = block - (*len % block);
    for (size_t i = 0; i < pad; i++) data[*len + i] = pad;
    *len += pad;
}

static int pkcs7_unpad(uint8_t *data, size_t *len, size_t block) {
    if (*len == 0 || *len % block != 0) return 0;
    size_t pad = data[*len - 1];
    if (pad == 0 || pad > block) return 0;
    for (size_t i = *len - pad; i < *len; i++) if (data[i] != pad) return 0;
    *len -= pad;
    return 1;
}

static char *base64_encode(const uint8_t *data, size_t len) {
    BIO *bio, *b64;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, len);
    BIO_flush(bio);
    BUF_MEM *ptr;
    BIO_get_mem_ptr(bio, &ptr);
    char *out = malloc(ptr->length + 1);
    memcpy(out, ptr->data, ptr->length);
    out[ptr->length] = 0;
    BIO_free_all(bio);
    return out;
}

static uint8_t *base64_decode(const char *str, size_t *out_len) {
    BIO *bio, *b64;
    size_t len = strlen(str);
    uint8_t *data = malloc(len);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(str, len);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *out_len = BIO_read(bio, data, len);
    BIO_free_all(bio);
    return data;
}

static int create_tar_from_path(const char *path, const char *outfile, int is_dir, int compress) {
    struct archive *a = archive_write_new();
    archive_write_set_format_pax_restricted(a);
    if (compress) archive_write_add_filter_lz4(a);
    else archive_write_add_filter_none(a);
    if (archive_write_open_filename(a, outfile) != ARCHIVE_OK) {
        archive_write_free(a);
        return 0;
    }
    if (is_dir) {
        DIR *dir = opendir(path);
        if (!dir) { archive_write_free(a); return 0; }
        struct dirent *de;
        while ((de = readdir(dir))) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
            char full[1024];
            snprintf(full, sizeof(full), "%s/%s", path, de->d_name);
            struct stat st;
            if (stat(full, &st) == 0 && S_ISREG(st.st_mode)) {
                struct archive_entry *entry = archive_entry_new();
                archive_entry_set_pathname(entry, de->d_name);
                archive_entry_set_size(entry, st.st_size);
                archive_entry_set_filetype(entry, AE_IFREG);
                archive_entry_set_perm(entry, st.st_mode);
                archive_write_header(a, entry);
                FILE *f = fopen(full, "rb");
                if (f) {
                    char buf[8192];
                    size_t n;
                    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
                        archive_write_data(a, buf, n);
                    fclose(f);
                }
                archive_entry_free(entry);
            }
        }
        closedir(dir);
    } else {
        glob_t g;
        if (glob(path, GLOB_NOCHECK, NULL, &g) == 0) {
            for (size_t i = 0; i < g.gl_pathc; i++) {
                const char *fname = g.gl_pathv[i];
                struct stat st;
                if (stat(fname, &st) == 0 && S_ISREG(st.st_mode)) {
                    struct archive_entry *entry = archive_entry_new();
                    const char *basename = strrchr(fname, '/');
                    basename = basename ? basename+1 : fname;
                    archive_entry_set_pathname(entry, basename);
                    archive_entry_set_size(entry, st.st_size);
                    archive_entry_set_filetype(entry, AE_IFREG);
                    archive_entry_set_perm(entry, st.st_mode);
                    archive_write_header(a, entry);
                    FILE *f = fopen(fname, "rb");
                    if (f) {
                        char buf[8192];
                        size_t n;
                        while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
                            archive_write_data(a, buf, n);
                        fclose(f);
                    }
                    archive_entry_free(entry);
                }
            }
            globfree(&g);
        }
    }
    archive_write_close(a);
    archive_write_free(a);
    return 1;
}

static int extract_tar_from_mem(const uint8_t *data, size_t len, const char *outdir) {
    struct archive *a = archive_read_new();
    archive_read_support_format_tar(a);
    archive_read_support_filter_all(a);
    if (archive_read_open_memory(a, (void*)data, len) != ARCHIVE_OK) return 0;
    struct archive_entry *entry;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", outdir, name);
        FILE *f = fopen(fullpath, "wb");
        if (f) {
            const void *buff;
            size_t size;
            int64_t offset;
            while (archive_read_data_block(a, &buff, &size, &offset) == ARCHIVE_OK)
                fwrite(buff, 1, size, f);
            fclose(f);
        }
        archive_entry_clear(entry);
    }
    archive_read_close(a);
    archive_read_free(a);
    return 1;
}

/*static void cbc_encrypt_stream(FILE *fin, FILE *fout, const uint8_t key[BLOCK_BYTES], size_t total, int quiet) {
    uint8_t iv[IV_SIZE];
    if (RAND_bytes(iv, IV_SIZE) != 1) return;
    fwrite(iv, 1, IV_SIZE, fout);
    uint8_t in[BLOCK_BYTES], out[BLOCK_BYTES];
    size_t processed = 0;
    size_t n;
    clock_t start = clock();
    while ((n = fread(in, 1, BLOCK_BYTES, fin)) > 0) {
        if (n < BLOCK_BYTES) pkcs7_pad(in, &n, BLOCK_BYTES);
        for (int i = 0; i < BLOCK_BYTES; i++) in[i] ^= iv[i % IV_SIZE];
        encrypt_block(in, key, out);
        memcpy(iv, out, IV_SIZE);
        fwrite(out, 1, BLOCK_BYTES, fout);
        processed += BLOCK_BYTES;
        if (!quiet && total && (processed % (BLOCK_BYTES*1024) == 0 || processed >= total)) {
            clock_t now = clock();
            double seconds = (double)(now - start) / CLOCKS_PER_SEC;
            double speed = (processed / 1024.0 / 1024.0) / seconds;
            int percent = (int)((double)processed / total * 100);
            fprintf(stderr, "\rEncrypting (CBC): %d%% (%.2f MB/s)", percent, speed);
            fflush(stderr);
        }
    }
    if (!quiet && total) {
        clock_t now = clock();
        double seconds = (double)(now - start) / CLOCKS_PER_SEC;
        double speed = (total / 1024.0 / 1024.0) / seconds;
        fprintf(stderr, "\rEncrypting (CBC): 100%% (%.2f MB/s)   \n", speed);
    }
}

static void cbc_decrypt_stream(FILE *fin, FILE *fout, const uint8_t key[BLOCK_BYTES], size_t total, int quiet) {
    uint8_t iv[IV_SIZE];
    if (fread(iv, 1, IV_SIZE, fin) != IV_SIZE) return;
    uint8_t in[BLOCK_BYTES], out[BLOCK_BYTES], prev_iv[IV_SIZE];
    memcpy(prev_iv, iv, IV_SIZE);
    size_t processed = 0;
    size_t n;
    clock_t start = clock();
    while ((n = fread(in, 1, BLOCK_BYTES, fin)) == BLOCK_BYTES) {
        decrypt_block(in, key, out);
        for (int i = 0; i < BLOCK_BYTES; i++) out[i] ^= prev_iv[i % IV_SIZE];
        memcpy(prev_iv, in, IV_SIZE);
        fwrite(out, 1, BLOCK_BYTES, fout);
        processed += BLOCK_BYTES;
        if (!quiet && total && (processed % (BLOCK_BYTES*1024) == 0 || processed >= total)) {
            clock_t now = clock();
            double seconds = (double)(now - start) / CLOCKS_PER_SEC;
            double speed = (processed / 1024.0 / 1024.0) / seconds;
            int percent = (int)((double)processed / total * 100);
            fprintf(stderr, "\rDecrypting (CBC): %d%% (%.2f MB/s)", percent, speed);
            fflush(stderr);
        }
    }
    if (n == 0) {
        fseek(fout, -BLOCK_BYTES, SEEK_END);
        uint8_t last[BLOCK_BYTES];
        fread(last, 1, BLOCK_BYTES, fout);
        size_t last_len = BLOCK_BYTES;
        if (!pkcs7_unpad(last, &last_len, BLOCK_BYTES)) return;
        fseek(fout, -BLOCK_BYTES, SEEK_END);
        fwrite(last, 1, last_len, fout);
        ftruncate(fileno(fout), ftell(fout));
    }
    if (!quiet && total) {
        clock_t now = clock();
        double seconds = (double)(now - start) / CLOCKS_PER_SEC;
        double speed = (total / 1024.0 / 1024.0) / seconds;
        fprintf(stderr, "\rDecrypting (CBC): 100%% (%.2f MB/s)   \n", speed);
    }
}
*/

static void ctr_encrypt_stream(FILE *fin, FILE *fout, const uint8_t key[BLOCK_BYTES], size_t total, int quiet) {
    uint8_t nonce[8];
    if (RAND_bytes(nonce, 8) != 1) return;
    fwrite(nonce, 1, 8, fout);
    uint8_t ctr[16];
    memset(ctr, 0, 16);
    memcpy(ctr, nonce, 8);
    uint8_t counter_block[BLOCK_BYTES];
    uint8_t keystream[BLOCK_BYTES];
    uint8_t data[BLOCK_BYTES];
    size_t processed = 0;
    clock_t start = clock();
    while (1) {
        size_t n = fread(data, 1, BLOCK_BYTES, fin);
        if (n == 0) break;
        memset(counter_block, 0, BLOCK_BYTES);
        memcpy(counter_block, ctr, 16);
        encrypt_block(counter_block, key, keystream);
        for (size_t i = 0; i < n; i++) data[i] ^= keystream[i];
        fwrite(data, 1, n, fout);
        for (int i = 15; i >= 0; i--) {
            if (++ctr[i] != 0) break;
        }
        processed += n;
        if (!quiet && total && (processed % (BLOCK_BYTES*1024) == 0 || processed >= total)) {
            clock_t now = clock();
            double seconds = (double)(now - start) / CLOCKS_PER_SEC;
            double speed = (processed / 1024.0 / 1024.0) / seconds;
            int percent = (int)((double)processed / total * 100);
            fprintf(stderr, "\rEncrypting (CTR): %d%% (%.2f MB/s)", percent, speed);
            fflush(stderr);
        }
    }
    if (!quiet && total) {
        clock_t now = clock();
        double seconds = (double)(now - start) / CLOCKS_PER_SEC;
        double speed = (total / 1024.0 / 1024.0) / seconds;
        fprintf(stderr, "\rEncrypting (CTR): 100%% (%.2f MB/s)   \n", speed);
    }
}

static void ctr_decrypt_stream(FILE *fin, FILE *fout, const uint8_t key[BLOCK_BYTES], size_t total, int quiet) {
    uint8_t nonce[8];
    if (fread(nonce, 1, 8, fin) != 8) return;
    uint8_t ctr[16];
    memset(ctr, 0, 16);
    memcpy(ctr, nonce, 8);
    uint8_t counter_block[BLOCK_BYTES];
    uint8_t keystream[BLOCK_BYTES];
    uint8_t data[BLOCK_BYTES];
    size_t processed = 0;
    size_t data_total = total - 8;
    if (data_total < 0) return;
    clock_t start = clock();
    while (processed < data_total) {
        size_t n = fread(data, 1, BLOCK_BYTES, fin);
        if (n == 0) break;
        memset(counter_block, 0, BLOCK_BYTES);
        memcpy(counter_block, ctr, 16);
        encrypt_block(counter_block, key, keystream);
        for (size_t i = 0; i < n; i++) data[i] ^= keystream[i];
        fwrite(data, 1, n, fout);
        for (int i = 15; i >= 0; i--) {
            if (++ctr[i] != 0) break;
        }
        processed += n;
        if (!quiet && total) {
            int percent = (int)((double)processed / data_total * 100);
            fprintf(stderr, "\rDecrypting (CTR): %d%%", percent);
            fflush(stderr);
        }
    }
    if (!quiet && total) {
        clock_t now = clock();
        double seconds = (double)(now - start) / CLOCKS_PER_SEC;
        double speed = (data_total / 1024.0 / 1024.0) / seconds;
        fprintf(stderr, "\rDecrypting (CTR): 100%% (%.2f MB/s)   \n", speed);
    }
}

typedef struct {
    uint8_t *data;
    size_t start;
    size_t end;
    const uint8_t *key;
    uint8_t nonce[8];
    uint64_t start_block;
    atomic_size_t *processed;
    int quiet;
} ctr_thread_arg;

static void *ctr_mmap_worker(void *arg) {
    ctr_thread_arg *ta = (ctr_thread_arg*)arg;
    uint8_t ctr[16];
    memset(ctr, 0, 16);
    memcpy(ctr, ta->nonce, 8);
    uint64_t block = ta->start_block;
    for (int i = 15; i >= 8; i--) {
        ctr[i] = block & 0xFF;
        block >>= 8;
    }
    uint8_t counter_block[BLOCK_BYTES];
    uint8_t keystream[BLOCK_BYTES];
    size_t pos = ta->start;
    while (pos < ta->end) {
        size_t n = ta->end - pos;
        if (n > BLOCK_BYTES) n = BLOCK_BYTES;
        memset(counter_block, 0, BLOCK_BYTES);
        memcpy(counter_block, ctr, 16);
        encrypt_block(counter_block, ta->key, keystream);
        for (size_t i = 0; i < n; i++) {
            ta->data[pos + i] ^= keystream[i];
        }
        for (int i = 15; i >= 8; i--) {
            if (++ctr[i] != 0) break;
        }
        pos += n;
        atomic_fetch_add(ta->processed, n);
    }
    return NULL;
}

static void ecb_encrypt(const uint8_t *in, size_t in_len, uint8_t out[BLOCK_BYTES], const uint8_t key[BLOCK_BYTES]) {
    uint8_t padded[BLOCK_BYTES];
    memcpy(padded, in, in_len);
    size_t padded_len = in_len;
    pkcs7_pad(padded, &padded_len, BLOCK_BYTES);
    encrypt_block(padded, key, out);
}

static int ecb_decrypt(const uint8_t in[BLOCK_BYTES], uint8_t *out, size_t *out_len, const uint8_t key[BLOCK_BYTES]) {
    uint8_t plain[BLOCK_BYTES];
    decrypt_block(in, key, plain);
    *out_len = BLOCK_BYTES;
    if (!pkcs7_unpad(plain, out_len, BLOCK_BYTES)) return 0;
    memcpy(out, plain, *out_len);
    return 1;
}

static void ctr_encrypt_mmap(const char *infile, const char *outfile, const uint8_t key[BLOCK_BYTES], int threads, int quiet) {
    int fd_in = open(infile, O_RDONLY);
    if (fd_in < 0) { perror("open input"); return; }
    struct stat st;
    fstat(fd_in, &st);
    size_t file_size = st.st_size;
    uint8_t *data = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd_in, 0);
    if (data == MAP_FAILED) { perror("mmap"); close(fd_in); return; }
    uint8_t nonce[8];
    if (RAND_bytes(nonce, 8) != 1) { munmap(data, file_size); close(fd_in); return; }
    FILE *fout = fopen(outfile, "wb");
    if (!fout) { perror("fopen out"); munmap(data, file_size); close(fd_in); return; }
    fwrite(nonce, 1, 8, fout);
    atomic_size_t total_processed = 0;
    pthread_t *threads_arr = malloc(threads * sizeof(pthread_t));
    ctr_thread_arg *args = malloc(threads * sizeof(ctr_thread_arg));
    size_t chunk = (file_size + threads - 1) / threads;
    for (int i = 0; i < threads; i++) {
        args[i].data = data;
        args[i].start = i * chunk;
        args[i].end = (i+1) * chunk;
        if (args[i].end > file_size) args[i].end = file_size;
        args[i].key = key;
        args[i].start_block = args[i].start / BLOCK_BYTES;
        memcpy(args[i].nonce, nonce, 8);
        args[i].processed = &total_processed;
        args[i].quiet = quiet;
        pthread_create(&threads_arr[i], NULL, ctr_mmap_worker, &args[i]);
    }
    for (int i = 0; i < threads; i++) {
        pthread_join(threads_arr[i], NULL);
    }
    fwrite(data, 1, file_size, fout);
    fclose(fout);
    munmap(data, file_size);
    close(fd_in);
    free(threads_arr);
    free(args);
}

static void ctr_decrypt_mmap(const char *infile, const char *outfile, const uint8_t key[BLOCK_BYTES], int threads, int quiet) {
    int fd_in = open(infile, O_RDONLY);
    if (fd_in < 0) { perror("open input"); return; }
    struct stat st;
    fstat(fd_in, &st);
    size_t file_size = st.st_size;
    if (file_size < 8) { close(fd_in); return; }
    uint8_t *data = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd_in, 0);
    if (data == MAP_FAILED) { perror("mmap"); close(fd_in); return; }
    uint8_t nonce[8];
    memcpy(nonce, data, 8);
    size_t data_size = file_size - 8;
    FILE *fout = fopen(outfile, "wb");
    if (!fout) { perror("fopen out"); munmap(data, file_size); close(fd_in); return; }
    atomic_size_t total_processed = 0;
    pthread_t *threads_arr = malloc(threads * sizeof(pthread_t));
    ctr_thread_arg *args = malloc(threads * sizeof(ctr_thread_arg));
    size_t chunk = (data_size + threads - 1) / threads;
    for (int i = 0; i < threads; i++) {
        args[i].data = data + 8;
        args[i].start = i * chunk;
        args[i].end = (i+1) * chunk;
        if (args[i].end > data_size) args[i].end = data_size;
        args[i].key = key;
        args[i].start_block = args[i].start / BLOCK_BYTES;
        memcpy(args[i].nonce, nonce, 8);
        args[i].processed = &total_processed;
        args[i].quiet = quiet;
        pthread_create(&threads_arr[i], NULL, ctr_mmap_worker, &args[i]);
    }
    for (int i = 0; i < threads; i++) {
        pthread_join(threads_arr[i], NULL);
    }
    fwrite(data + 8, 1, data_size, fout);
    fclose(fout);
    munmap(data, file_size);
    close(fd_in);
    free(threads_arr);
    free(args);
}

int main(int argc, char **argv) {

    init_lut();

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Cube512 — 512-bit block cipher\n\n");
            printf("Usage: %s --in <source> --key <key> --action encrypt|decrypt [options]\n\n", argv[0]);
            printf("Required:\n");
            printf("  --in <source>       Input: file, folder/, text, or - (stdin)\n");
            printf("  --key <key>         Key (file path or text)\n");
            printf("  --action <action>   encrypt or decrypt\n\n");
            printf("Options:\n");
            printf("  --out <file>        Output file (required for binary mode)\n");
            printf("  --threads <N>       Threads for CTR mode (default: 1)\n");
            printf("  --compress          Compress with LZ4 (only for folders)\n");
            printf("  --quiet             Suppress progress output\n");
            printf("  --help, -h          Show this help\n\n");
            printf("Examples:\n");
            printf("  %s --in secret.txt --key my.key --action encrypt --out secret.enc\n", argv[0]);
            printf("  %s --in \"hello world\" --key pass --action encrypt\n", argv[0]);
            printf("  %s --in ./docs/ --key key.txt --action encrypt --out docs.enc --compress\n", argv[0]);
            return 0;
        }
    }

    const char *input = NULL, *key_str = NULL, *action = NULL, *output = NULL;
    int compress = 0, quiet = 0;
    int threads = 1;

    static struct option long_opts[] = {
        {"in", required_argument, 0, 'i'},
        {"key", required_argument, 0, 'k'},
        {"action", required_argument, 0, 'a'},
        {"out", required_argument, 0, 'o'},
        {"compress", no_argument, 0, 'z'},
        {"quiet", no_argument, 0, 'q'},
        {"threads", required_argument, 0, 't'},
        {0,0,0,0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "i:k:a:o:zq:t:", long_opts, NULL)) != -1) {
        switch (c) {
            case 'i': input = optarg; break;
            case 'k': key_str = optarg; break;
            case 'a': action = optarg; break;
            case 'o': output = optarg; break;
            case 'z': compress = 1; break;
            case 'q': quiet = 1; break;
            case 't': threads = atoi(optarg); if (threads < 1) threads = 1; break;
            default: return 1;
        }
    }

    if (!input || !key_str || !action) {
        fprintf(stderr, "Usage: %s --in <source> --key <key> --action encrypt|decrypt [--out <file>] [--compress] [--threads N] [--quiet]\n", argv[0]);
        return 1;
    }

    const char *real_input = input;
    int is_stdin = (strcmp(real_input, "-") == 0);
    int is_dir = (!is_stdin && real_input[strlen(real_input)-1] == '/');
    int is_glob = (!is_stdin && !is_dir && (strchr(real_input, '*') || strchr(real_input, '?')));
    int is_file = (!is_stdin && !is_dir && !is_glob);
    int is_text = 0;

    if (is_file) {
        struct stat st;
        if (stat(real_input, &st) != 0) {
            is_file = 0;
            is_text = 1;
        }
    }

    uint8_t key[BLOCK_BYTES];
    if (key_str[0] == '"' || key_str[0] == '\'') {
        size_t klen = strlen(key_str);
        char *key_tmp = strdup(key_str);
        key_tmp[klen-1] = '\0';
        derive_key(key_tmp+1, strlen(key_tmp+1), key);
        free(key_tmp);
    } else {
        struct stat st;
        if (stat(key_str, &st) == 0 && S_ISREG(st.st_mode)) {
            if (!read_key_from_file(key_str, key)) {
                fprintf(stderr, "Cannot read key file\n");
                return 1;
            }
        } else {
            derive_key(key_str, strlen(key_str), key);
        }
    }

    if (is_text) {
        if (strcmp(action, "encrypt") == 0) {
            uint8_t encrypted[BLOCK_BYTES];
            ecb_encrypt((const uint8_t*)real_input, strlen(real_input), encrypted, key);
            char *b64 = base64_encode(encrypted, BLOCK_BYTES);
            printf("%s\n", b64);
            free(b64);
        } else if (strcmp(action, "decrypt") == 0) {
            size_t bin_len;
            uint8_t *bin = base64_decode(real_input, &bin_len);
            if (!bin || bin_len != BLOCK_BYTES) {
                fprintf(stderr, "Invalid base64 input\n");
                free(bin);
                return 1;
            }
            uint8_t dec[BLOCK_BYTES];
            size_t dec_len;
            if (!ecb_decrypt(bin, dec, &dec_len, key)) {
                fprintf(stderr, "Decryption failed\n");
                free(bin);
                return 1;
            }
            fwrite(dec, 1, dec_len, stdout);
            printf("\n");
            free(bin);
        } else {
            fprintf(stderr, "Unknown action\n");
        }
        return 0;
    }

    if (!output) {
        fprintf(stderr, "Error: --out is required for file/directory/glob/stream mode\n");
        return 1;
    }

    if (strcmp(action, "encrypt") == 0) {
        if (is_stdin) {
            FILE *fin = stdin;
            FILE *fout = (strcmp(output, "-") == 0) ? stdout : fopen(output, "wb");
            if (!fout) { perror("fopen out"); return 1;}
            ctr_encrypt_stream(fin, fout, key, 0, quiet);
            if (fout != stdout) fclose(fout);
        } else if (is_file) {
            struct stat st;
            if (stat(real_input, &st) != 0) { perror("stat input");  return 1; }
            if (threads > 1) {
                ctr_encrypt_mmap(real_input, output, key, threads, quiet);
                FILE *fin = fopen(real_input, "rb");
                FILE *fout = fopen(output, "wb");
                if (!fin || !fout) { perror("fopen"); return 1; }
                ctr_encrypt_stream(fin, fout, key, st.st_size, quiet);
                fclose(fin); fclose(fout);
            } else {
                FILE *fin = fopen(real_input, "rb");
                FILE *fout = fopen(output, "wb");
                if (!fin || !fout) { perror("fopen"); return 1; }
                ctr_encrypt_stream(fin, fout, key, st.st_size, quiet);
                fclose(fin); fclose(fout);
            }
        } else {
            char tmp_tar[] = "/tmp/cube_tar_XXXXXX";
            int fd = mkstemp(tmp_tar);
            if (fd < 0) { perror("mkstemp"); return 1; }
            close(fd);
            if (!create_tar_from_path(real_input, tmp_tar, is_dir || is_glob, compress)) {
                fprintf(stderr, "Failed to create tar\n");
                unlink(tmp_tar);
                return 1;
            }
            struct stat st;
            stat(tmp_tar, &st);
            size_t total = st.st_size;
            if (threads > 1 && !is_dir && !is_glob && !is_stdin && total > 0) {
                ctr_encrypt_mmap(tmp_tar, output, key, threads, quiet);
                unlink(tmp_tar);
                return 0;
            } else {
                FILE *fin = fopen(tmp_tar, "rb");
                FILE *fout = fopen(output, "wb");
                if (!fin || !fout) { perror("fopen"); unlink(tmp_tar); return 1; }
                ctr_encrypt_stream(fin, fout, key, total, quiet);
                fclose(fin); fclose(fout);
                unlink(tmp_tar);
            }
        }
    } else if (strcmp(action, "decrypt") == 0) {
        if (is_stdin) {
            FILE *fin = stdin;
            FILE *fout = (strcmp(output, "-") == 0) ? stdout : fopen(output, "wb");
            if (!fout) { perror("fopen out"); return 1; }
            ctr_decrypt_stream(fin, fout, key, 0, quiet);
            if (fout != stdout) fclose(fout);
        } else {
            struct stat st;
            stat(real_input, &st);
            size_t total = st.st_size;
            if (threads > 1 && !is_dir && !is_glob && !is_stdin && total >= 8) {
                ctr_decrypt_mmap(real_input, output, key, threads, quiet);
            } else {
                char tmp_dec[] = "/tmp/cube_dec_XXXXXX";
                int fd = mkstemp(tmp_dec);
                if (fd < 0) { perror("mkstemp"); return 1; }
                close(fd);
                FILE *fin = fopen(real_input, "rb");
                FILE *ftmp = fopen(tmp_dec, "wb");
                if (!fin || !ftmp) { perror("fopen"); unlink(tmp_dec); return 1; }
                ctr_decrypt_stream(fin, ftmp, key, total, quiet);
                fclose(fin); fclose(ftmp);
                FILE *ftest = fopen(tmp_dec, "rb");
                uint8_t magic[257];
                size_t n = fread(magic, 1, 257, ftest);
                fclose(ftest);
                int is_tar = (n >= 257 && memcmp(magic, "ustar", 5) == 0);
                if (is_tar) {
                    if (mkdir(output, 0755) != 0 && errno != EEXIST) {
                        perror("mkdir");
                        unlink(tmp_dec);
                        return 1;
                    }
                    FILE *ftardata = fopen(tmp_dec, "rb");
                    fseek(ftardata, 0, SEEK_END);
                    long tar_len = ftell(ftardata);
                    fseek(ftardata, 0, SEEK_SET);
                    uint8_t *tar_buf = malloc(tar_len);
                    if (tar_buf) {
                        fread(tar_buf, 1, tar_len, ftardata);
                        fclose(ftardata);
                        extract_tar_from_mem(tar_buf, tar_len, output);
                        free(tar_buf);
                    } else {
                        fclose(ftardata);
                    }
                } else {
                    FILE *fout = fopen(output, "wb");
                    if (fout) {
                        FILE *fin_raw = fopen(tmp_dec, "rb");
                        char buf[8192];
                        size_t n2;
                        while ((n2 = fread(buf, 1, sizeof(buf), fin_raw)) > 0)
                            fwrite(buf, 1, n2, fout);
                        fclose(fin_raw);
                        fclose(fout);
                    } else {
                        perror("fopen out");
                    }
                }
                unlink(tmp_dec);
            }
        }
    } else {
        fprintf(stderr, "Unknown action\n");
        return 1;
    }
    return 0;
}
