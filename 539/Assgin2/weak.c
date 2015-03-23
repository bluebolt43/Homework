#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include "md5.h"
#include <limits.h>
// input : ./prog key

unsigned int key;
int buf, n, infile;

decrypt(char* path)
{
  struct stat st;
  int size,fsize;
  int *temp, result;   
  int rollingkey;    
	int stage=0;
  //rollingkey = key;
	int i, key;
  infile = open (path, O_RDONLY);
  if (infile<0) { printf("input open error\n"); exit(0); }
  
  buf = 0;
  read(infile,&buf,4);
  size=buf; // get plaintext size

  // ciphertext has xtra 4 bytes (size) and padding 

  stat(path, &st); fsize = st.st_size; // get ciphertext size
  if ((fsize < 8)||(size>fsize)||(size<(fsize-8))) {printf("file size sanity check failed\n");}; 

	if((n = read(infile, &buf, 4))> 0){
		printf("possible PDF key %x\n", buf ^ 0x46445025);
		printf("possible PNG key %x\n", buf ^ 0x474e5089);
	}
	close(infile);

};

main(int argc, char *argv[])
{
	decrypt (argv[1]);
	return 0;
};
