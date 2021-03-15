#include <stdio.h>
#include <stdlib.h>
int main() {
	setvbuf(stdout, NULL, _IONBF, 0); /* turn off buffering */
	setvbuf(stdin,  NULL, _IONBF, 0); /* turn off buffering */
	char secret[] = "Secret Secret! I've got a secret!";
	char buf[128];
	while (1) {
		printf("$ ");
		fgets(buf, sizeof(buf), stdin);
		if (feof(stdin)) {
			exit(1);
		}
		printf(buf);
	}
}
