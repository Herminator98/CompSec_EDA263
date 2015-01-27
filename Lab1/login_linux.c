/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -Wall -g -o mylogin login.linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
/* Uncomment next line in step 2 */
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler() {
	
	printf("  <-- signal caught\n");	
	/* add signalhandling routines here */
	/* see 'man 2 signal' */
}

int main(int argc, char *argv[]) {

	mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important[LENGTH] = "***IMPORTANT***";
	//char *const a = {"-c", "env", 0};
	//char *const b = "PATH=/bin";
	char user[LENGTH];
	char *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;
	
	char *args[2];
		args[0] = "/bin/bash";
		args[1] = NULL;

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		signal(SIGINT, sighandler);
		signal(SIGQUIT, sighandler);
		signal(SIGTSTP, sighandler);
		printf("Value of variable 'important' before input of login name: %s\n",
		important);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */
		fgets(user, LENGTH, stdin); /* gets() is vulnerable to buffer */
		//	exit(0); /*  overflow attacks.  */
		
		strtok(user, "\n");
		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);

		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */
			c_pass = crypt(user_pass, passwddata->passwd_salt);
			bzero(user_pass, LENGTH);
			if(passwddata->pwfailed >= 3){
				printf("The account is locked!\n");
				return(-1);
			} else if(!strcmp(c_pass, passwddata->passwd)) {
				
				printf(" You're in !\n");
				printf("%d failed login attempts since last login.\n", passwddata->pwfailed);
				passwddata->pwfailed = 0;
				if(setuid(passwddata->uid) == 0) {
					mysetpwent(user, passwddata);
					execve(args[0], args, NULL);
				} else {
					printf("setuid failed");		
				}
				return(1);
				
				if (++passwddata->pwage > 10) {
					printf("Your password is old, you should change it!\n");
				}
				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */

			} else {
				passwddata->pwfailed++;
				printf("Login Incorrect \n");
			}
			mysetpwent(user, passwddata);
		} else {
			printf("Login Incorrect \n");
		}
		
	}
	return 0;
}

