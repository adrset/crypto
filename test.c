#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv){
	FILE* p = fopen("dane.txt", "w"); 
	if(p == NULL){
		return -1;
	}
	int rng1,rng2;
	char buff[16];
	int urnd = open("/dev/random", O_RDONLY);
	int rnd = open("/dev/random", O_RDONLY);
	
	// /proc/sys/kernel/random/entropy_avail

	int buffer[8];
	int loopCount = 0;

	if( !urnd || !rnd){
		return -1;
	}

	while(1){
		int entAvail = open("/proc/sys/kernel/random/entropy_avail", O_RDONLY);
		int br1 = read(urnd, &rng1, sizeof(int));
		int br2 = read(rnd, &rng2, sizeof(int));
		int bytesRead = read(entAvail, buff, 16);
		printf("urandom: %02x\n", rng1);
		printf(" random: %02x\n", rng2);
	
		printf("\nBytes: %d\n", bytesRead);
		printf("enavail: %s\n", buff);
		close(entAvail);

		buffer[loopCount%8];
		loopCount++;
		if(loopCount % 8 == 0){
			size_t wrEl = fwrite( buffer, sizeof(int),sizeof(buffer)/sizeof(int), p );
		}
		getchar();
		

	}
	close(rnd);
	close(urnd);
	
	return 0;
}

