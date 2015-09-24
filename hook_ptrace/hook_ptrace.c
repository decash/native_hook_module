/*
 *  Collin's Binary Instrumentation Tool/Framework for Android
 *  Collin Mulliner <collin[at]mulliner.org>
 *  http://www.mulliner.org/android/
 *
 *  (c) 2012,2013
 *
 *  License: LGPL v2.1
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <string.h>
#include <termios.h>
#include <pthread.h>
#include <sys/ptrace.h>

#include <jni.h>
#include <stdlib.h>

#include "../base/hook.h"
#include "../base/base.h"

#undef log

#define log(...) \
        {FILE *fp = fopen("/data/local/tmp/temp.log", "a+"); if (fp) {\
        fprintf(fp, __VA_ARGS__);\
        fclose(fp);}}


// this file is going to be compiled into a thumb mode binary

void __attribute__ ((constructor)) my_init(void);

static struct hook_t eph;


// arm version of hook
extern int my_ptrace_arm(int request, int pid, void* addr, void* data);

/*  
 *  log function to pass to the hooking library to implement central loggin
 *
 *  see: set_logfunction() in base.h
 */
static void my_log(char *msg)
{
	log("%s", msg);
}

int my_ptrace(int request, int pid, void* addr, void* data)
{
	int (*orig_ptrace)(int request, int pid, void* addr, void* data);
	orig_ptrace = (void*)eph.orig;

	log("pre ptrace() called\n");
	hook_precall(&eph);

	int res = 0;
	if(request == 0)
	{
		log("DETECT AntiDebuggin!!!!!!!!!\n");
	}
	else
	{
		log("ptrace() called\n");
		log("(int request, int pid, void* addr, void* data);\n");
		log("(request : %d, pid : %d, mypid: %d\n", request, pid, getpid());

		int res = orig_ptrace(request, pid, addr, data);
	}

	log("poset ptrace()\n");
	hook_postcall(&eph);

	log("end ptrace()\n\n");

	return res;
}

void my_init(void)
{
	log("%s started\n", __FILE__)
 
	set_logfunction(my_log);

	hook(&eph, getpid(), "libc.", "ptrace", my_ptrace_arm, my_ptrace);
}

