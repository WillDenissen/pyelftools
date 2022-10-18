#include <stdio.h>

int remove (const char *__filename){}
int rename (const char *__old, const char *__new){}
int renameat (int __oldfd, const char *__old, int __newfd, const char *__new){}
FILE *tmpfile (void){}
char *tmpnam (char *__s){}
char *tmpnam_r (char *__s){}
char *tempnam (const char *__dir, const char *__pfx){}
int fclose (FILE *__stream){}
int fflush (FILE *__stream){}
int fflush_unlocked (FILE *__stream){}
FILE *fopen (const char *__restrict __filename, const char *__restrict __modes){}
FILE *freopen (const char *__restrict __filename, const char *__restrict __modes, FILE *__restrict __stream){}
FILE *fdopen (int __fd, const char *__modes){}
FILE *fmemopen (void *__s, size_t __len, const char *__modes){}
FILE *open_memstream (char **__bufloc, size_t *__sizeloc){}
void setbuf (FILE *__restrict __stream, char *__restrict __buf){}
int setvbuf (FILE *__restrict __stream, char *__restrict __buf, int __modes, size_t __n){}
void setbuffer (FILE *__restrict __stream, char *__restrict __buf, size_t __size){}
void setlinebuf (FILE *__stream){}
int fprintf (FILE *__restrict __stream, const char *__restrict __format, ...){}
int printf (const char *__restrict __format, ...){}
int sprintf (char *__restrict __s, const char *__restrict __format, ...){}
int vfprintf (FILE *__restrict __s, const char *__restrict __format, __gnuc_va_list __arg){}
int vprintf (const char *__restrict __format, __gnuc_va_list __arg){}
int vsprintf (char *__restrict __s, const char *__restrict __format, __gnuc_va_list __arg){}
int snprintf (char *__restrict __s, size_t __maxlen, const char *__restrict __format, ...){}
int vsnprintf (char *__restrict __s, size_t __maxlen, const char *__restrict __format, __gnuc_va_list __arg){}
int vdprintf (int __fd, const char *__restrict __fmt, __gnuc_va_list __arg){}
int dprintf (int __fd, const char *__restrict __fmt, ...){}
int fscanf (FILE *__restrict __stream, const char *__restrict __format, ...){}
int scanf (const char *__restrict __format, ...){}
int sscanf (const char *__restrict __s, const char *__restrict __format, ...){}
int vfscanf (FILE *__restrict __s, const char *__restrict __format, __gnuc_va_list __arg){}
int vscanf (const char *__restrict __format, __gnuc_va_list __arg){}
int vsscanf (const char *__restrict __s, const char *__restrict __format, __gnuc_va_list __arg){}
int fgetc (FILE *__stream){}
int getc (FILE *__stream){}
int getchar (void){}
int getc_unlocked (FILE *__stream){}
int getchar_unlocked (void){}
int fgetc_unlocked (FILE *__stream){}
int fputc (int __c, FILE *__stream){}
int putc (int __c, FILE *__stream){}
int putchar (int __c){}
int fputc_unlocked (int __c, FILE *__stream){}
int putc_unlocked (int __c, FILE *__stream){}
int putchar_unlocked (int __c){}
int getw (FILE *__stream){}
int putw (int __w, FILE *__stream){}
char *fgets (char *__restrict __s, int __n, FILE *__restrict __stream){}
__ssize_t __getdelim (char **__restrict __lineptr, size_t *__restrict __n, int __delimiter, FILE *__restrict __stream){}
__ssize_t getdelim (char **__restrict __lineptr, size_t *__restrict __n, int __delimiter, FILE *__restrict __stream){}
__ssize_t getline (char **__restrict __lineptr, size_t *__restrict __n, FILE *__restrict __stream){}
int fputs (const char *__restrict __s, FILE *__restrict __stream){}
int puts (const char *__s){}
int ungetc (int __c, FILE *__stream){}
size_t fread (void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __stream){}
size_t fwrite (const void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __s){}
size_t fread_unlocked (void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __stream){}
size_t fwrite_unlocked (const void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __stream){}
int fseek (FILE *__stream, long int __off, int __whence){}
long int ftell (FILE *__stream){}
void rewind (FILE *__stream){}
int fseeko (FILE *__stream, __off_t __off, int __whence){}
__off_t ftello (FILE *__stream){}
int fgetpos (FILE *__restrict __stream, fpos_t *__restrict __pos){}
int fsetpos (FILE *__stream, const fpos_t *__pos){}
void clearerr (FILE *__stream){}
int feof (FILE *__stream){}
int ferror (FILE *__stream){}
void clearerr_unlocked (FILE *__stream){}
int feof_unlocked (FILE *__stream){}
int ferror_unlocked (FILE *__stream){}
void perror (const char *__s){}
int fileno (FILE *__stream){}
int fileno_unlocked (FILE *__stream){}
FILE *popen (const char *__command, const char *__modes){}
int pclose (FILE *__stream){}
char *ctermid (char *__s){}
void flockfile (FILE *__stream){}
int ftrylockfile (FILE *__stream){}
void funlockfile (FILE *__stream){}
