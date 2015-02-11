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
#include <errno.h>
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16
#define MAX_LOGIN_ATTEMPTS 3
#define SETUID_SUCCESS 0
#define OLD_PW 10

void sighandler() {
	//"Signal handling", not sure what else to do here
	printf("  <-- signal caught\n");	
}

int main(int argc, char *argv[]) {

	mypwent *passwddata; 	//(this has to be redefined in step 2) - done

	char important[LENGTH] = "***IMPORTANT***";
	char user[LENGTH];
	char *c_pass; 			//crypted password
	char prompt[] = "password: ";
	char *user_pass;
	
	//Init of array used for execve()
	char *exargs[2];
	exargs[0] = "/bin/bash";
	exargs[1] = NULL;


	while (TRUE) {

		//handling signal, sending them to sighandler();
		signal(SIGINT, sighandler);
		signal(SIGQUIT, sighandler);
		signal(SIGTSTP, sighandler);

		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important' before input of login name: %s\n",
			important);

		printf("login: ");
		fflush(NULL); 			/* Flush all  output buffers */
		__fpurge(stdin); 		/* Purge any data in stdin buffer */
		fgets(user, LENGTH, stdin); 	/* gets() is vulnerable to buffer overflow 
						attacks. Changed to fgets() */
		
		strtok(user, "\n");		/*removing newline created by fgets(), 
						appending null-terminated instead. */

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important' after input of login name: %*.*s\n",
			LENGTH - 1, LENGTH - 1, important);

		passwddata = mygetpwnam(user);
		user_pass = getpass(prompt);
		
		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */
			if(passwddata->pwfailed >= MAX_LOGIN_ATTEMPTS ){  
				printf("The account is locked!\n");
				exit(EACCES);
			} 
			c_pass = crypt(user_pass, passwddata->passwd_salt); //encrypting pw
			bzero(user_pass, LENGTH);	//clearing the user_pass variable
			if(NULL == c_pass){		//if c_pass is null then crypt() failed
				exit(ENODATA);
			}
			//if wrong password over 3 times, you can't log in,
			// admin must lower the number manually
			if(!strcmp(c_pass, passwddata->passwd)) {
				//If the password match, try to set UID
				if(setuid(passwddata->uid) == SETUID_SUCCESS) {
					//If UID get set, print some, resest pwfaild count, 
					//launch new bash
					if (++passwddata->pwage > OLD_PW ) {
						//Just a reminder, no need to exit or quit.
						printf("Your password is old, you should change it!\n");
					}
					printf(" You're in !\n");
					printf("%d failed login attempts since last login.\n", passwddata->pwfailed);
					passwddata->pwfailed = 0;
					mysetpwent(user, passwddata);
					if(execve(exargs[0], exargs, NULL)){
						exit(errno);
					}
				} else {
					printf("setuid failed");
					exit(EACCES);	//access denied	
				}
			} else {
				//If the wrong pw is entered, inc pwfailed and print message
				passwddata->pwfailed++;
				mysetpwent(user, passwddata);
				printf("Login Incorrect \n");
			}
		} else {
			printf("Login Incorrect \n");
		}	
	}
	return 0;
}

