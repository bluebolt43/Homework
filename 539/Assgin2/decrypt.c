#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "md5.h"

// input : ./prog key

unsigned int key;
int buf, n, infile, outfile;
MD5_CTX mdContext; 


int lastbytes(int outfile, int size, int buf) // magic code for extracting last bytes of encryption without the padding
{ 
  int i = 0;
  char *last;
  last = (char*) &buf;
  for (i=0;i<size;i++) {write(outfile, &last[i], 1);} 
};

int decrypt(int key, char* path)
{
  struct stat st;
  int size,fsize;
  int *temp, result;   
  int rollingkey;    
  rollingkey = key;   
 
  infile = open (path, O_RDONLY);
  if (infile<0) { printf("input open error\n"); exit(0); }
  
  buf = 0;
  read(infile,&buf,4);
  size=buf; // get plaintext size

  // ciphertext has xtra 4 bytes (size) and padding 

  stat(path, &st); fsize = st.st_size; // get ciphertext size
  if ((fsize < 8)||(size>fsize)||(size<(fsize-8))) {printf("file size sanity check failed\n");}; 

  outfile = open ("output-dec", O_RDWR|O_CREAT|O_TRUNC, 0700);
  if (outfile<0) { printf("output open error\n"); exit(0); }
  
  while ((n = read(infile, &buf, 4))> 0) {
		//printf("buf= %x, key= %x\n",buf,rollingkey);
      buf = buf ^ rollingkey; // doing the reverse of encrypt
	//printf("result %x\n",buf);
//getchar();
      MD5Init(&mdContext);
      MD5Update(&mdContext,(unsigned char *) &rollingkey, 4);
      MD5Final(&mdContext);
      temp = (int *) &mdContext.digest[12]; 
      result = *temp; // result is 32 bits of MD5 of key
      rollingkey = rollingkey ^ result; // new key

      if (size >= 4) write(outfile, &buf, 4);  
      else lastbytes(outfile, size, buf);

      buf = 0;  // repeat, keep track of output size in size.
      size = size - 4;
  };
};

int main(int argc, char *argv[])
{
  int key;

  sscanf(argv[1], "%x", &key); 
//  printf("%x\n", key);
  decrypt (key,argv[2]);
return 0;
};
