/*
 * steg.c - LSB image steganography for 24-bit BMP files (C99)
 *
 * Build : gcc -std=c99 -O2 -Wall -Wextra -o steg src/steg.c
 * Use   : ./steg encode in.bmp out.bmp "secret"
 *         ./steg decode out.bmp
 *         ./steg info   in.bmp
 *         ./steg                (interactive menu)
 *
 * Payload layout, one bit per pixel byte (MSB first):
 *   "STG1" | length (u32, big endian) | FNV-1a checksum (u32) | message bytes
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAGIC     "STG1"
#define HDR_BYTES 12                     /* magic + length + checksum */

typedef struct {
    uint8_t *d;                          /* whole file, loaded once   */
    size_t   size, off, rowb, stride, rows;
} Bmp;

typedef struct { uint8_t *p; size_t col; const Bmp *b; } Cur;

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint32_t fnv1a(const uint8_t *p, size_t n) {
    uint32_t h = 2166136261u;
    while (n--) { h ^= *p++; h *= 16777619u; }
    return h;
}

/* Load and validate a 24-bit uncompressed BMP. Returns 1 on success. */
static int bmp_load(const char *path, Bmp *b) {
    const char *err = NULL;
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 0; }
    b->d = NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    if (n < 54) err = "file too small to be a BMP";
    else if (!(b->d = malloc((size_t)n))) err = "out of memory";
    else if (fread(b->d, 1, (size_t)n, f) != (size_t)n) err = "read error";
    fclose(f);
    if (!err) {
        const uint8_t *h = b->d;
        int32_t w = (int32_t)rd32(h + 18), ht = (int32_t)rd32(h + 22);
        if (ht < 0) ht = -ht;                          /* top-down BMPs */
        if (h[0] != 'B' || h[1] != 'M')          err = "not a BMP file";
        else if (h[28] != 24 || rd32(h + 30))    err = "need an uncompressed 24-bit BMP";
        else if (w <= 0 || ht <= 0)              err = "invalid dimensions";
        else {
            b->size = (size_t)n;  b->off = rd32(h + 10);
            b->rowb = (size_t)w * 3;
            b->stride = (b->rowb + 3) & ~(size_t)3;   /* rows pad to 4 bytes */
            b->rows = (size_t)ht;
            if (b->off < 54 || b->off + b->stride * b->rows > b->size) err = "truncated pixel data";
        }
    }
    if (err) { fprintf(stderr, "%s: %s\n", path, err); free(b->d); return 0; }
    return 1;
}

/* Payload capacity in bytes (padding bytes are never touched). */
static size_t capacity(const Bmp *b) {
    size_t bytes = b->rowb * b->rows / 8;
    return bytes > HDR_BYTES ? bytes - HDR_BYTES : 0;
}

/* Cursor walks pixel bytes row by row, skipping row padding. No division per bit. */
static void cur_init(Cur *c, const Bmp *b) { c->p = b->d + b->off; c->col = 0; c->b = b; }

static uint8_t *cur_next(Cur *c) {
    uint8_t *r = c->p;
    if (++c->col == c->b->rowb) { c->col = 0; c->p += c->b->stride - c->b->rowb + 1; }
    else c->p++;
    return r;
}

static void put_byte(Cur *c, uint8_t v) {
    for (int i = 7; i >= 0; i--) { uint8_t *p = cur_next(c); *p = (uint8_t)((*p & 0xFE) | ((v >> i) & 1)); }
}
static uint8_t get_byte(Cur *c) {
    uint8_t v = 0;
    for (int i = 0; i < 8; i++) v = (uint8_t)((v << 1) | (*cur_next(c) & 1));
    return v;
}
static void put32(Cur *c, uint32_t v) { for (int s = 24; s >= 0; s -= 8) put_byte(c, (uint8_t)(v >> s)); }
static uint32_t get32(Cur *c) { uint32_t v = 0; for (int i = 0; i < 4; i++) v = v << 8 | get_byte(c); return v; }

static int encode(const char *in, const char *out, const char *msg) {
    Bmp b;
    if (!bmp_load(in, &b)) return 1;
    size_t n = strlen(msg), cap = capacity(&b);
    if (n == 0 || n > cap) {
        fprintf(stderr, "Message is %zu bytes; this image holds 1..%zu bytes.\n", n, cap);
        free(b.d); return 1;
    }
    Cur c; cur_init(&c, &b);
    for (int i = 0; i < 4; i++) put_byte(&c, (uint8_t)MAGIC[i]);
    put32(&c, (uint32_t)n);
    put32(&c, fnv1a((const uint8_t *)msg, n));
    for (size_t i = 0; i < n; i++) put_byte(&c, (uint8_t)msg[i]);

    FILE *f = fopen(out, "wb");                    /* one buffered write */
    int ok = f && fwrite(b.d, 1, b.size, f) == b.size;
    if (f && fclose(f) != 0) ok = 0;
    if (!ok) perror(out); else printf("Encoded %zu bytes into %s (capacity %zu).\n", n, out, cap);
    free(b.d);
    return ok ? 0 : 1;
}

static int decode(const char *in) {
    Bmp b;
    if (!bmp_load(in, &b)) return 1;
    int rc = 1;
    if (capacity(&b) == 0) { fprintf(stderr, "Image too small.\n"); goto done; }
    Cur c; cur_init(&c, &b);
    for (int i = 0; i < 4; i++)
        if (get_byte(&c) != (uint8_t)MAGIC[i]) { fprintf(stderr, "No hidden message found.\n"); goto done; }
    uint32_t n = get32(&c), sum = get32(&c);
    if (n == 0 || n > capacity(&b)) { fprintf(stderr, "Corrupt length field.\n"); goto done; }
    uint8_t *m = malloc((size_t)n + 1);
    if (!m) { fprintf(stderr, "Out of memory.\n"); goto done; }
    for (uint32_t i = 0; i < n; i++) m[i] = get_byte(&c);
    m[n] = '\0';
    if (fnv1a(m, n) != sum) fprintf(stderr, "Checksum mismatch: the image was altered.\n");
    else { printf("Hidden message: %s\n", m); rc = 0; }
    free(m);
done:
    free(b.d);
    return rc;
}

static int info(const char *in) {
    Bmp b;
    if (!bmp_load(in, &b)) return 1;
    printf("%s: %zu x %zu px, data offset %zu, capacity %zu bytes\n",
           in, b.rowb / 3, b.rows, b.off, capacity(&b));
    free(b.d);
    return 0;
}

static void ask(const char *prompt, char *buf, size_t n, const char *def) {
    printf("%s [%s]: ", prompt, def);
    if (!fgets(buf, (int)n, stdin)) buf[0] = '\0';
    buf[strcspn(buf, "\r\n")] = '\0';
    if (!buf[0]) { strncpy(buf, def, n - 1); buf[n - 1] = '\0'; }
}

static void menu(void) {
    char line[16], a[256], o[256], m[1024];
    for (;;) {
        puts("\n===== IMAGE STEGANOGRAPHY SYSTEM =====\n1. Encode Message\n2. Decode Message\n3. Exit");
        printf("Enter your choice: ");
        if (!fgets(line, sizeof line, stdin)) return;
        switch (atoi(line)) {
        case 1: ask("Input BMP", a, sizeof a, "input.bmp");
                ask("Output BMP", o, sizeof o, "encoded.bmp");
                ask("Message", m, sizeof m, "Hello, steganography!");
                encode(a, o, m); break;
        case 2: ask("Stego BMP", a, sizeof a, "encoded.bmp"); decode(a); break;
        case 3: puts("Exiting Program..."); return;
        default: puts("Invalid choice!");
        }
    }
}

int main(int argc, char **argv) {
    if (argc == 1) { menu(); return 0; }
    if (argc == 5 && !strcmp(argv[1], "encode")) return encode(argv[2], argv[3], argv[4]);
    if (argc == 3 && !strcmp(argv[1], "decode")) return decode(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "info"))   return info(argv[2]);
    fprintf(stderr, "usage: %s encode in.bmp out.bmp \"msg\" | decode in.bmp | info in.bmp\n", argv[0]);
    return 2;
}
