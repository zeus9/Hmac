#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "md5.h"

#define KEY_SIZE 4  // in bytes
char* outputFileName = "output";
int fileSize;      // in bytes
MD5_CTX mdContext; // needed to compute MD5

char *encrypt(char *name, int key)
{
    unsigned char *fileData;
    int buf, n, infile, outfile;
    struct stat st;
    int i, j;
    int *temp, result;
    int rollingkey;

    // priliminaries, get files ready and sized
    infile = open(name, O_RDONLY);
    if (infile < 0)
    {
        printf("input file %s open error\n", name);
        exit(0);
    }

    outfile = open(outputFileName, O_RDWR | O_CREAT | O_TRUNC, 0700);
    if (outfile < 0)
    {
        printf("Cannot access file: %s\n", outputFileName);
        exit(0);
    }

    stat(name, &st);
    fileSize = st.st_size;
    if (fileSize < 4)
    {
        printf("input file too small\n");
        exit(0);
    };

    // write(outfile, &size, 4); // write input file size to output

    // do the encryption, buf contains plaintext, and rollingkey contains key
    buf = 0;
    rollingkey = key;
    i = 0;
    unsigned char *charBuf = (unsigned char *)&buf;
    fileData = (char *)malloc(fileSize);

    while ((n = read(infile, &buf, 4)) > 0)
    {
        buf = buf ^ rollingkey; //XOR with key, and put ciphertext in buf
        MD5Init(&mdContext);    // compute MD5 of rollingkey
        MD5Update(&mdContext, &rollingkey, 4);
        MD5Final(&mdContext);
        temp = (int *)&mdContext.digest[12];
        result = *temp; // result is 32 bits of MD5 of buf

        rollingkey = rollingkey ^ result; // new key
        write(outfile, &buf, 4);          // write ciphertext

        fileData[i] = charBuf[0];
        fileData[i + 1] = charBuf[1];
        fileData[i + 2] = charBuf[2];
        fileData[i + 3] = charBuf[3];

        i = i + 4;

        buf = 0; // rinse and repeat
    };

    fileData[i] = '\0';

    close(infile);
    close(outfile);

    return (fileData);
};

int hash(char *str_to_hash, int size)
{
    int *pass_pointer, *temp, result;
    pass_pointer = (int *)str_to_hash;

    MD5Init(&mdContext); // compute MD5 of password
    MD5Update(&mdContext, pass_pointer, size);
    MD5Final(&mdContext);
    temp = (int *)&mdContext.digest[12];
    result = *temp; // result is 32 bits of MD5.

    return result;
}

bool isLittleEndian()
{
    int x = 1;

    char *y = (char *)&x;

    return (bool)(*y + 48);
}

void ToLittleEndian(char *str, int size)
{
    for (int i = 0, j = size - 1; i < j; i++, j--)
    {
        char temp = str[i];
        str[i] = str[j];
        str[j] = temp;
    }
}

void strconcat(char *dest, char *adder, int finalSize)
{
    int i = 0;
    for (i = 0; i < finalSize; i++)
    {
        dest[i + 4] = adder[i];
    }
    dest[i] = '\0';
}

void main(int argc, char *argv[])
{
    int keyInt;
    char keyChar[KEY_SIZE];
    char* filename = argv[1];

    sscanf(argv[2], "%8x", &keyInt);
    sscanf(argv[2], "%8x", keyChar);

    // unsigned char *filename = "1024bytes";

    if (isLittleEndian())
    {
        ToLittleEndian(keyChar, KEY_SIZE);
    }

    char *data = encrypt(filename, keyInt);

    char *toHash = malloc(fileSize + KEY_SIZE);

    strcpy(toHash, keyChar);
    strconcat(toHash, data, fileSize + KEY_SIZE);

    printf("Expected hash: %x \nOutput: %s\n", hash(toHash, fileSize + KEY_SIZE), outputFileName);
}
