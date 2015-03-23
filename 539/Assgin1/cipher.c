#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEYLENG 4 //KEY 32BITs = 4chars
#define DEFAULT_OUTPUT "output"
#define CAESAR_X 0xC5

int main (int args,char **argv)
{
	unsigned char key[KEYLENG+1];
	FILE* input;
	FILE* output;
	int debug = 1;
	int crypt = 0;
	switch(args){
		case 6:
			debug=atoi(argv[5]);
		case 5:
			output = fopen(argv[4], "w+");
		case 4:
			if(args<5)
				output = fopen("output", "w+");				
			input = fopen(argv[3], "r");
			if(input!=NULL){
				strncpy(key, argv[2], KEYLENG);
				crypt=atoi(argv[1]);
				break;
			}
			printf("Can not open input file %s\n", argv[3]);
			if(args==4)
				fclose(output);
		default:
			printf("Wrong argument\n%s [0-1] [Key] [input] [output]\n 0 is encrypt 1 is decrypt.\n",argv[0]);
			return 1;
	}
	if(debug){
		printf("INPUT: %s\nOUTPUT: %s\nKEY: %s\n%s\n", argv[3], (args<5)?"output":argv[4], key, crypt?"Decrypt":"Encrypt");
	}
	//XOR ciper
	//Electronic codebook
	int i;
	size_t result;
	unsigned char in[KEYLENG];//plaintext length as same as key length
	unsigned char out;
	do{
		result = fread (in, sizeof(unsigned char), KEYLENG, input);
		for(i=0;i<result;i++){
			out = in[i] + (crypt?0:CAESAR_X);//Add first value
			out = out ^ key[i];//ciper
			out = out - (crypt?CAESAR_X:0);//Add second value
			fwrite(&out, sizeof(unsigned char), 1, output);
			if(debug==2)
				printf("IN'%04x'KEY'%04x'OUT'%04x'\n", in[i],key[i],out);
		}
	}while(result == KEYLENG);

	fclose(input);
	fclose(output);
	return 0;
}
