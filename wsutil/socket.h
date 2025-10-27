/** @file
 * Socket wrappers
 *
 * Copyright 2016, Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __SOCKET_H__
#define __SOCKET_H__

#include <wireshark.h>

#if defined(_WIN32) && !defined(__CYGWIN__)
	#include <windows.h>
	#include <ws2tcpip.h>
	#include <winsock2.h>
	#include <process.h>

	#define socket_handle_t SOCKET
	#define socklen_t int
#else
	/*
	 * UN*X, or Windows pretending to be UN*X with the aid of Cygwin.
	 */
	#ifdef HAVE_UNISTD_H
		/*
		 * For close().
		 */
		#include <unistd.h>
	#endif
	#ifdef HAVE_SYS_SOCKET_H
		#include <sys/socket.h>
	#endif

	#define closesocket(socket)	close(socket)
	#define socket_handle_t		int
#ifndef INVALID_SOCKET
	#define INVALID_SOCKET		(-1)
#endif
	#define SOCKET_ERROR		(-1)
#endif

#ifdef HAVE_ARPA_INET_H
	#include <arpa/inet.h>
#endif

#ifdef HAVE_NETINET_IN_H
	#include <netinet/in.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @brief Initializes the socket subsystem.
 *
 * Performs any necessary platform-specific setup for socket operations.
 *
 * @return NULL on success, or a g_malloc()ed error message string on failure.
 *         The caller is responsible for freeing the returned string.
 */
WS_DLL_PUBLIC char *ws_init_sockets(void);

/**
 * @brief Cleans up the socket subsystem.
 *
 * Performs any necessary platform-specific cleanup for socket operations.
 */
WS_DLL_PUBLIC void ws_cleanup_sockets(void);

/**
 * @brief Converts a string representation of an IP address and port into a sockaddr.
 *
 * Converts a string of the form `ipv4_address:port` or `[ipv6_address]:port`
 * into a `sockaddr_storage` structure. If the port is omitted, `def_port` is used.
 *
 * @param dst Pointer to a sockaddr_storage structure to receive the parsed address.
 * @param src The input string containing the address and optional port.
 * @param def_port The default port to use if none is specified (in host byte order).
 * @return 0 on success, or -1 on failure (e.g., invalid format or address).
 */
WS_DLL_PUBLIC int ws_socket_ptoa(struct sockaddr_storage *dst, const char *src, uint16_t def_port);

#ifdef	__cplusplus
}
#endif

#endif /* __SOCKET_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
