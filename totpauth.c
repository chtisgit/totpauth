#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

#ifdef __linux__
#include <linux/seccomp.h>
#include <sys/prctl.h>
#endif

#include "c_otp/src/rfc6238.h"
#include "c_otp/lib/utils.h"

#define B32KEY_MAXLEN 32
#define DIGITS 6
#define PERIOD 30

const int LoginGraceTime = 60; // seconds

static ssize_t r(int fd, void *buf, size_t count)
{
	const size_t c = count;
	while(count != 0){
		ssize_t n = read(fd, buf, count);
		if(n == -1){
			return -1;
		}

		buf = (void*) (((char*) buf) + n);
		count -= n;
	}
	return c;
}

static ssize_t w(int fd, const void *buf, size_t count)
{
	const size_t c = count;
	while(count != 0){
		ssize_t n = write(fd, buf, count);
		if(n == -1){
			return -1;
		}

		buf = (void*) (((char*) buf) + n);
		count -= n;
	}
	return c;
}

#define ws(fd,str) (w(fd,str,sizeof(str)-1))

static int readnum(long *val)
{
	char buf[DIGITS+1], *endptr;

	for(;;) { 
		if(r(STDIN_FILENO, buf, 1) == -1)
			return 0;
	
		if(isdigit(buf[0]))
			break;
	}

	ssize_t n = r(STDIN_FILENO, buf+1, DIGITS-1);

	if(n == -1)
		return 0;

	assert(n >= 0 && n <= DIGITS);
	buf[n+1] = '\0';

	*val = strtol(buf, &endptr, 10);

	return endptr == buf+DIGITS;
}

static int check_code(const unsigned char* b32key, size_t keysize, uint32_t code, time_t t) {
	unsigned char key[keysize];
	memcpy(key, b32key, sizeof(key));

	unsigned char *k = key;
	unsigned char **u = &k;
	
	const size_t key_len = decode_b32key(u, keysize); 
	uint32_t correctcode = TOTP(key, key_len, t/PERIOD, DIGITS);

	explicit_bzero(key, sizeof(key));
	return correctcode == code;
}

static int check_code_now(const unsigned char* b32key, size_t keysize, uint32_t code, int multi) {
	time_t t = time(NULL) - multi*PERIOD;
	for(int i = -multi; i <= multi; i++){
		if(check_code(b32key, keysize, code, t)){
			return 1;
		}
		t += PERIOD;
	}
	return 0;
}

static int prompt(const unsigned char* b32key, size_t b32key_len)
{
	for(int tries = 3; tries != 0; tries--){
		ws(STDOUT_FILENO, "Provide your passcode: ");

		long code;
		if(readnum(&code) && code >= 0){
			if(check_code_now(b32key, b32key_len, (uint32_t) code, 1)){
				ws(STDOUT_FILENO, "Enjoy your shell\n");
				return 0;
			}
		}
		ws(STDOUT_FILENO, "Try again.\n\n");
	}
	return 1;
}

static int readkey(char *buf, int *len, int max)
{
	const char *home = getenv("HOME");
	char path[1000];
	path[0] = '\0';
	strncat(path, home, 999);
	strncat(path, "/.ssh/totpkey", 999);
	
	FILE *f = fopen(path, "rb");
	if(f == NULL)
		return 0;

	const size_t to = fread(buf, 1, (size_t) max, f);
	size_t i;
	for(i = 0; i < to; i++){
		if(!isalnum(buf[i])){
			buf[i] = '\0';
			break;
		}
	}
	*len = i;


	fclose(f);
	return 1;
}

int main()
{
	pid_t child = fork();
	if(child == -1)
		abort();

	if(child == 0) {
		// this is the child process
		unsigned char *b32key = malloc(B32KEY_MAXLEN);
		int b32key_len = 0;

		if(b32key == NULL)
			return 1;

		if(!readkey(b32key, &b32key_len, B32KEY_MAXLEN))
			return 1;

#ifdef __linux__
		// seccomp limits the totp library too much, apparantly
		//if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) != 0)
			//abort();
#endif

		if(getuid() == 0){
			chroot("/tmp");
			setregid(65000,65000);
			setreuid(65000,65000);
		}

		int status = prompt(b32key, b32key_len);

		explicit_bzero(b32key, B32KEY_MAXLEN);
		free(b32key);

		return status;
	}else{
		// wait for the child
		int status;
		int count = LoginGraceTime;

		while((count--) != 0){
			sleep(1);
			if(waitpid(child, &status, WNOHANG) == child){
				if(status != 0)
					abort();
				execl("/bin/bash", "/bin/bash", NULL);
				abort();
			}
		}
		kill(child, SIGKILL);
		abort();
	}
	return 0;
}

