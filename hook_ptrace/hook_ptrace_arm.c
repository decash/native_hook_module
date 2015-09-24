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

#include <sys/types.h>
#include <sys/ptrace.h>

//extern int my_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
extern int my_ptrace(int request, int pid, void* addr, void* data);

//int my_epoll_wait_arm(int epfd, struct epoll_event *events, int maxevents, int timeout)
int my_ptrace_arm(int request, int pid, void* addr, void* data)
{
	//return my_epoll_wait(epfd, events, maxevents, timeout);
	return my_ptrace(request, pid, addr, data);
}
