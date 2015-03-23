#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include "md5.h"
#include <limits.h>
// input : ./prog key
#define DUMP_LIST 0

unsigned int key;
int buf, n;
FILE* infile;
MD5_CTX mdContext; 

decrypt(char* path)
{
	struct stat st;
	int size,fsize,recover_size;
	int *temp, result;   
	int rollingkey;    
	int stage=0;
	int i, key;

	infile = fopen (path, "rb" );

	if (infile==NULL) { printf("input open error\n"); exit(0); }

	fseek (infile , 0 , SEEK_END);
	long lSize = ftell (infile);
	rewind (infile);
	int* buffer = (int*) calloc (lSize+3,sizeof(char));
	if (buffer == NULL) {printf ("Memory error\n"); exit (2);}
	result = fread (buffer,1,lSize,infile);  
	size=buffer[0]; // get plaintext size


	// ciphertext has xtra 4 bytes (size) and padding 

	stat(path, &st); fsize = st.st_size; // get ciphertext size
	if ((fsize < 8)||(size>fsize)||(size<(fsize-8))) {printf("file size sanity check failed\n");}; 

	for(key=0x00000000;key<0xffffffff;key++){
		if((key<<4)==0)
			printf("Trying 0x%08x-0x%08x\n",key,key|0xfffffff);

		rollingkey = buffer[1] ^ key; // doing the reverse of encrypt
		if(rollingkey==0x46445025){
			printf("possible PDF key %x\n", key);
		}else if(rollingkey==0x474e5089){
			printf("possible PNG key %x\n", key);
		}

		size=4;
		stage=0;
		rollingkey = key; // doing the reverse of encrypt
		while(size<=buffer[0]){
			buf = buffer[size>>2] ^ rollingkey; // doing the reverse of encrypt
			//ASCII check
			int total=4;
			if (buffer[0] - size < 4) total=buffer[0]-size;
			char* last = (char*) &buf;
			for (i=0;i<total;i++) {
				if((last[i]>=32 && last[i]<=126) || last[i]==9 || last[i]==10 || last[i]==13){
					stage=1;
				}else{
					stage=0;
					break;
				}
			}
			if(stage==0) break;

			MD5Init(&mdContext);
			MD5Update(&mdContext, &rollingkey, 4);
			MD5Final(&mdContext);
			temp = (int *) &mdContext.digest[12]; 
			result = *temp; // result is 32 bits of MD5 of key
			rollingkey = rollingkey ^ result; // new key

			buf = 0;  // repeat, keep track of output size in size.
			size = size + 4;
		};
		if(stage==1){
			printf("possible text key %x\n", key);
		}
	}
	fclose(infile);

};

main(int argc, char *argv[])
{
	if(argc < 2){
		printf("%s [PATH]\nPATH is the path of decrypt file\n",argv[0]);
		exit(0);
	}

	decrypt (argv[1]);
	return 0;
};
