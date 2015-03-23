/*************************************************************************
  FileName:		rainbow.c
  Description:	
		
  Usage:	
  History:
	  <author>			<time>			<desc>
	  Kuan-hao Chen		15.03.19		Create
*************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "md5.h" 

#define HASH_LOOKUPTABLE 1
#define RAINBOW_RAND 0
#define SHOW_BRUTE_FORCE 1

#define PW_SIZE (62 * 62 * 62 * 62)

int list [] = { 0x19fbc7c1, 0x7e1d96fd, 0x88df723c, 0x3974cffc, 0x8f6bb61b, 0x8e564270, 0x655ca818, 0x58712b2b, 0x97e75d32, 0x14928501};
char map[] = {'a','b','c','d','e','f','g','h','i','j',\
				'k','l','m','n','o','p','q','r','s','t',\
				'u','v','w','x','y','z','A','B','C','D',\
				'E','F','G','H','I','J','K','L','M','N',\
				'O','P','Q','R','S','T','U','V','W','X',\
				'Y','Z','0','1','2','3','4','5','6','7',\
				'8','9'};
unsigned int* hash_table;//id
unsigned int* chain_start;//id
unsigned int* chain_end;//id
int* marked_table;
int table_size = PW_SIZE;

unsigned int hashing(int pw) {

	unsigned int *temp;
	MD5_CTX mdContext;
	MD5Init(&mdContext);  // compute MD5 of password
	MD5Update(&mdContext, &pw, 4);
	MD5Final(&mdContext);
	temp = (unsigned int *) &mdContext.digest[12];

	return *temp;
}

unsigned int pw2id(unsigned int pw){
	int i, j, id = 0;
	char* pass = (char*)&pw;
	for(i=3; i>=0; i--){
		id *= 62;
		for(j=0; j<62; j++){
			if(pass[i]==map[j])
				id += j;
		}
	}
	return id;
}

unsigned int id2pw(unsigned int id){
	unsigned int i;
	char pass[4];
	for(i=0; i<4; i++, id/=62){
		pass[i] = map[id%62];
	}
	i = *(unsigned int*)pass;
	return i;
}

unsigned int reduction(unsigned int hash, unsigned int i) {
	return (hash+i)%table_size;
}
#if HASH_LOOKUPTABLE
void Build_table()
{
	int i;
	for(i=0; i<table_size; i++){
		hash_table[i] = hashing(id2pw(i));
	}
}
#endif
int crack_brute(unsigned int hash)//Brute force
{
	int i, tmp;
	for(i=0; i<table_size; i++){
		if(hash == hashing(id2pw(i))){
			return id2pw(i);
		}
	}
	return -1;
}

void Build_rainbow(int chain_size, int chain_length, int seed)
{
	int i, j, tmp;
	time_t t1, t2;
	marked_table=(int*)calloc(table_size,sizeof(int));

	t1 = time(NULL);
#if RAINBOW_RAND
	srand(seed);
	for(i=0; i<chain_size;){
		tmp = rand()%table_size;//id
		for(j=0 ; j<i; j++){//Reduce dupilcation
			if(marked_table[tmp]==1)
				break;
			if(tmp==chain_start[j])
				break;
		}
		if(j==i){
#else
	for(i=0, seed=0; (i<chain_size) && (seed<table_size); seed++){
		tmp=seed;//id
		if(marked_table[tmp]==0){//Reduce dupilcation
#endif
			chain_start[i] = tmp;/*id*/
			chain_end[i] = tmp;/*id*/
			for(j=0; j< chain_length; j++){
				marked_table[chain_end[i]] = 1;
#if HASH_LOOKUPTABLE
				chain_end[i] = hash_table[chain_end[i]];
#else
				chain_end[i] = hashing(id2pw(chain_end[i]));
#endif
				chain_end[i]/*id*/ = reduction(chain_end[i]/*pw*/, j);
			}
			i++;
		}
	}
	t2 = time(NULL);

	//compte coverage
	for(i=0, j=0; i<table_size; i++){
		if(marked_table[i]==1){
			j++;
		}
	}
	printf("Rainbow table info\n\tcoverage %.02f%% chains length %d chains # %d\n\ttime usage: %d seconds\n",\
				((double)j/(double)table_size)*100.f, chain_length, chain_size, (int)difftime(t2, t1));
	free(marked_table);
}

unsigned int/*pw*/ crack_rainbow(unsigned int hash/*id*/, int chain_size, int chain_length)
{
	int i, j, k;
	unsigned int pass, tmp;
	for(i=0; i<chain_length; i++){
		//worst case reduction times: (1+chain_length)*chain_length/2
		tmp/*id*/ = reduction(hash,chain_length-i-1);
		for(j=0; j<i; j++){
			tmp = hashing(id2pw(tmp));
			tmp/*id*/ = reduction(tmp,chain_length-i+j);
		}

		for(k=0; k<chain_size; k++){
			if(tmp==chain_end[k]){
				//printf("matching on chain #%05d at length %d\n", k, chain_length-1-i);
				tmp = chain_start[k];
				for(j=0; j<chain_length; j++){
					//printf("%d %.4s\n",j,(char*)& pass);
					pass = id2pw(tmp);
					tmp = hashing(pass);
					if(hash==tmp)
						return pass;
					tmp = reduction(tmp,j);
				}
			}
		}
	}

	return -1;
}

unsigned int find(unsigned int hash, int chain_size, int chain_length){
	time_t t1, t2;
	unsigned int pw;

	printf("Cracking hash %x\n",hash);
#if SHOW_BRUTE_FORCE
	t1 = time(NULL);
	pw = crack_brute(hash);
	t2 = time(NULL);
	printf(" Brute force :passwd %.4s , %d seconds\n", (char*)& pw, (int)difftime(t2, t1));
#endif
	t1 = time(NULL);
	pw = crack_rainbow(hash, chain_size, chain_length);
	t2 = time(NULL);
	if(pw!=-1)
		printf("Rainbow table:passwd %.4s , %d seconds\n", (char*)& pw, (int)difftime(t2, t1));
	else
		printf("Rainbow table:Not in table, %d seconds\n", (int)difftime(t2, t1));
}

int main(int argc, char *argv[])
{
	int i;
	FILE * pFile;
	int seed = 0;
	int chain_size = 100000;
	int chain_length = 500;

	if(argc<3){
		printf("%s chain_size chain_length [rainbow.dat]\n", argv[0]);
	}else{
		chain_size = atoi(argv[1]);
		chain_length = atoi(argv[2]);
	}
	chain_start = (unsigned int*)calloc(chain_size, sizeof(unsigned int));
	chain_end = (unsigned int*)calloc(chain_size, sizeof(unsigned int));

	if(argc==4){
		pFile = fopen (argv[3],"r");
		if (pFile!=NULL){
			for(i=0; i<chain_size; i++){
				fscanf(pFile, "%x %x\n", &chain_start[i], &chain_end[i]);
			}
			fclose(pFile);
			printf("Load rainbow table finished\n");
			//Crack hash
			for(i=0;i<10;i++){
				find(list[i], chain_size, chain_length);
			}
		}
	}else{
#if HASH_LOOKUPTABLE
		hash_table = (unsigned int*)calloc(table_size, sizeof(unsigned int));
		pFile = fopen ("table.dat","r");
		if (pFile!=NULL){
			for(i=0; i<table_size; i++){
				fscanf(pFile, "%x\n", &hash_table[i]);
			}
			fclose(pFile);
			printf("Load Brute force table finished\n");
		}else{
			Build_table();
			pFile = fopen ("table.dat","a+");//132MB
			for(i=0; i<table_size; i++){
				fprintf (pFile, "%x\n", hash_table[i]);
			}
			fclose(pFile);
			printf("Build brute force table finished\n");
		}
#endif
		Build_rainbow(chain_size, chain_length, seed);
		printf("Build rainbow table finished\n");		
		pFile = fopen ("rainbow.dat","a+");
		for(i=0; i<chain_size; i++){
			fprintf(pFile, "%x %x\n", chain_start[i], chain_end[i]);
		}
		fclose(pFile);
		free(hash_table);
	}
	free(chain_start);
	free(chain_end);
	return 0;
}
