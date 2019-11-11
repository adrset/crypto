#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <unistd.h>
#include <stdlib.h>
int main(int argc, char **argv){
	FILE* p = fopen("dane.txt", "w"); 
	setvbuf( p, (char *)NULL, _IONBF, 0 );
	if(p == NULL){
		return -1;
	}
	int rng1,rng2;
	char buff[16];
	int rnd = open("/dev/random", O_RDONLY);
	
	// /proc/sys/kernel/random/entropy_avail
	// check buffering impact!
	double buffer[8];
	int buffer_time[8];

	int ent=0;
	int loopCount = 0;

	if(!rnd){
		return -1;
	}
	fd_set          s;
	printf("%d", sizeof(int));
	    struct timeval  timeout;

	timeout.tv_sec = 0;
	timeout.tv_usec = 100000;
	int time = 0;
	do {
		int entAvail = open("/proc/sys/kernel/random/entropy_avail", O_RDONLY);

		int br2 = read(rnd, &rng2, sizeof(int));
		int bytesRead = read(entAvail, buff, 16);

		printf(" random: %02x\n", rng2);
	
	//	printf("\nBytes: %d\n", bytesRead);
		printf("enavail: %lf\n", atof(buff));
		close(entAvail);

		buffer[loopCount%8] = atoi(buff);
		buffer_time[loopCount++%8] = time;
		if(loopCount % 8 == 0){
			for(int i =0;i<8;i++){
				fprintf(p, "%d %.0lf\n", buffer_time[i], buffer[i]);
			}
			puts("Writing 8 chunks to file.");
		}
		//getchar();
		usleep(1000000);
		time += 1;
		fflush(stdout);
		FD_ZERO(&s);
		FD_SET(STDIN_FILENO, &s);
		select(STDIN_FILENO+1, &s, NULL, NULL, &timeout);
	} while (FD_ISSET(STDIN_FILENO, &s) == 0);

	fclose(p);
	close(rnd);

	
	return 0;
}

