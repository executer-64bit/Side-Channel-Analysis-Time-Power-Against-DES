#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include "utils.h"
#include "des.h"
#include "pcc.h"

#define SIX_BIT_MASK 0xFC0000000000

uint64_t *ct;
float *t; 
void readFile(char *auxName, int auxSample);

float getAvg(float *timeSet, int sizeDataset);
uint64_t getMaxDiff(float *timeDiffSet, int numberGuess);

/*main
 * Description:
 * 	PoC to leak subkey last round through side channel analysis through timing.
 * Input: 
 * 	Number of arguments (argc) it has to be three.
 * 	The arguments (argv) it has to be the nameOfExecutable binaryOfSamples numberSamples
 * Output:
 * 	0 if everithing went well.
*/ 
int main(int argc, char **argv) {
  int n, i, totalSbox = 8, hweight = 0,s = 1, auxMaskShift = 0x6;
  uint64_t r16l16, l16;
  uint64_t maxKey=64, extractedNibble[totalSbox], fullInputSbox=0x0;
  uint64_t gk=0, xoredGkeyL16 = 0x0, auxBitShift = 42;
  uint64_t expandedL16=0x0, outSbox = 0x0, auxMask = SIX_BIT_MASK;
  unsigned int j = 0, m = 0;
  float getAvgDiff[64];
  float auxAvgFast, auxAvgSlow;

  if(!des_check()) {
    ERROR(0, -1, "DES functional test failed");
  }

  if(argc != 3) {
    ERROR(0, -1, "usage: ta <datafile> <nexp>\n");
  }
  n = atoi(argv[2]);
  float timeFast[n];
  float timeSlow[n];
  if(n < 1) {
    ERROR(0, -1, "number of experiments to use (<nexp>) shall be greater than 1 (%d)", n);
  }
  readFile(argv[1], n);

  for(s=1; s <= totalSbox; s++){
	  for(gk=0;gk < maxKey; gk++){
		  for(i=0; i<n; i++){
			  r16l16 = des_ip(ct[i]);
			  l16 = des_right_half(r16l16);
			  //printf("Right 0x%lx\n", l16);
			  expandedL16 = des_e(l16);
			  //fprintf(stderr,"Before expended 0x%lx\n", expandedL16);
			  expandedL16 = expandedL16 & auxMask;
			  //printf("Mid expended 0x%lx\n", expandedL16);
			  expandedL16 = expandedL16 >> auxBitShift;
			  //printf("After expended 0x%lx\n", expandedL16);
			  xoredGkeyL16 = expandedL16 ^ gk; //6-bit
			  //printf("Xored 0x%lx -- s %d\n", xoredGkeyL16, s);
			  outSbox = des_sbox(s, xoredGkeyL16);
			  //printf("Out SBox 0x%lx\n", outSbox);
			  hweight = hamming_weight(outSbox);
			  //printf("Hamming weight = %d\n", hweight);
			  if(hweight <= 0x1){
				  //printf("%d Time %f\n",i, t[i]);
				  timeFast[m] = (float) t[i];
				  //printf("%d %f\n",m, timeFast[m]);
				  m++;
			  }
			  else if(hweight >= 0x3){
				  timeSlow[j] = t[i];
				  j++;
			  }
		  }
		  //printf("%d %f\n",m, timeFast[m-1]);
		  auxAvgFast = getAvg(timeFast,m);
		  auxAvgSlow = getAvg(timeSlow,j);
		  //printf("Avg of time fast = %f - Slow %f\n", auxAvgFast, auxAvgSlow);
		  getAvgDiff[gk] = auxAvgSlow - auxAvgFast;
		  //printf("%ld %d Done %f\n", gk, m, getAvgDiff[gk]);
		  //printf("%ld Done\n", gk);
		  memset(timeFast, 0, sizeof(timeFast));
		  memset(timeSlow, 0, sizeof(timeSlow));
		  m = 0;
		  j = 0;
	  }
	  extractedNibble[s-1] = getMaxDiff(getAvgDiff, maxKey);
	  //printf("This is the most likely value 0x%lx\n", extractedNibble);
	  auxMask = auxMask >> auxMaskShift;
	  auxBitShift = auxBitShift - auxMaskShift;
	  //printf("New Mask 0x%lx - New Bit shift 0x%lx\n", auxMask, auxBitShift);
	  for (int k = 0; k < maxKey; k++) {
    		getAvgDiff[k] = 0.0f;
	  }
  }
  for(s=0; s < totalSbox; s++){
	  fullInputSbox =  (fullInputSbox << 6) | (extractedNibble[s] & 0x3F);
  }
  fflush(stdout);
  printf("0x%lx", fullInputSbox);
  free(ct);
  free(t);
  return 0;
}

/*readFile
 * Description:
 * 	It reads ta.dat.example which is a binary provided by professor that contains the samples:
 *	message, ciphertex, and its time trace.
 * Input: 
 * 	The file name (auxName), and the number of samples (auxSample)
 * Output:
 * 	No output as they are stored in the allocated memory regions for ciphertext (ct) & time traces (t).
*/ 

void readFile(char *auxName, int auxSample) {
  int x;
  FILE *fileDesc;
  fileDesc = XFOPEN(auxName, "r");
  ct = XCALLOC(auxSample, sizeof(uint64_t));
  t = XCALLOC(auxSample, sizeof(float));
  for(x = 0; x < auxSample; x++) {
    if(fscanf(fileDesc, "%" PRIx64 " %f", &(ct[x]), &(t[x])) != 2) {
      ERROR(, -1, "Something went wrong");
    }
    //printf("Time %f\n", t[1]);
  }
}


/*getAvg
 * Description:
 * 	It calcualtes the average time:
 * 		AccumulatedTime/Number of samples in that array
 * Input: 
 * 	The array with traces (timeSet), and its number of samples (sizeDataset)
 * Output:
 * 	The result of the average operation (avgResult).
*/ 

float getAvg(float *timeSet, int sizeDataset){
	float auxAccumulation = 0.0, avgResult = 0.0;
	int i = 0;
	//printf("%d - Time set %f\n", sizeDataset, timeSet[sizeDataset-1]);
	for(i = 0; i < sizeDataset; i++){
		auxAccumulation = auxAccumulation + timeSet[i];
		//printf("Accumulation = %f\n", auxAccumulation);
	}
	avgResult = auxAccumulation/(float)sizeDataset;
	//printf("avgResult = %f\n", avgResult);
	return avgResult;
}

/*getMaxDiff
 * Description:
 * 	Detects the highest value of the array and the guess key representation.
 * Input: 
 * 	The array with all the substrations of the averages (timeDiffSet), and number of guesses (numberGuess)
 * Output:
 * 	The key representation of the highest difference (representedChar).
*/ 
uint64_t getMaxDiff(float *timeDiffSet, int numberGuess){
	float highestDiff = -1e9, auxDiff = 0.0;
	int i = 0;
	uint64_t representedChar = 0;
	for(i = 0; i < numberGuess; i++){
		auxDiff = timeDiffSet[i];
		if(auxDiff > highestDiff){
			highestDiff = auxDiff;
			representedChar = (uint64_t)i;
			//printf("New highest %f -> %ld\n",highestDiff, representedChar);
		}
	}
	return representedChar;
}
