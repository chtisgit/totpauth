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


const unsigned char b32key[] = "JBSWY3DPEHPK3PXP";
const int b32key_len = sizeof(b32key)-1;


int check_code(const unsigned char* b32key, size_t keysize, const char* code, time_t t) {
	unsigned char key[keysize];
	memcpy(key, b32key, sizeof(key));

	unsigned char *k = (unsigned char**) key;
	unsigned char **u = &k;
	
	const size_t key_len = decode_b32key(u, b32key_len); 
	uint32_t x = TOTP(key, key_len, t/30, 6);
	uint32_t y = (uint32_t) atoi(code);

	explicit_bzero(key, sizeof(key));
	return x == y;
}

int check_code_now(const unsigned char* b32key, size_t keysize, const char* code, int multi) {
	time_t t = time(NULL) - multi*30;
	for(int i = -multi; i <= multi; i++){
		if(check_code(b32key, keysize, code, t)){
			return 1;
		}
		t += 30;
	}
	return 0;
}


int main()
{
	pid_t child = fork();
	if(child == -1)
		abort();

	if(child == 0) {
		// this is the child process

#ifdef __linux__
		// seccomp limits the totp library too much, apparantly
		//if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) != 0)
			//abort();
#endif
		chroot("/tmp");
		setregid(65000,65000);
		setreuid(65000,65000);

		char buf[500];

		for(int tries = 3; tries != 0; tries--){
			ws(STDOUT_FILENO, "Provide your passcode: ");
			r(STDIN_FILENO, buf, 6);
			if(check_code_now(b32key, b32key_len, buf, 1)){
				ws(STDOUT_FILENO, "Enjoy your shell\n");
				return 0;
			}
			ws(STDOUT_FILENO, "Try again.\n\n");
		}
		return 1;

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

