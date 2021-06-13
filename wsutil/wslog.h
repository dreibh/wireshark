/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2021 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSLOG_H__
#define __WSLOG_H__

#include <ws_symbol_export.h>
#include <glib.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Descending order by priority needs to be maintained. Higher priorities have
 * lower values.
 */
enum ws_log_level {
     LOG_LEVEL_NONE,       /* not user facing */
     LOG_LEVEL_ERROR,      /* "error" is always fatal (aborts) */
     LOG_LEVEL_CRITICAL,
     LOG_LEVEL_WARNING,
     LOG_LEVEL_MESSAGE,
     LOG_LEVEL_INFO,
     LOG_LEVEL_DEBUG,
     _LOG_LEVEL_LAST
};

#include <ws_log_domains.h>

#ifndef WS_LOG_DOMAIN
#define WS_LOG_DOMAIN LOG_DOMAIN_DEFAULT
#endif


/** Signature for registering a log writer. */
typedef void (ws_log_writer_t)(const char *message,
                                   enum ws_log_domain domain,
                                   enum ws_log_level level,
                                   void *user_data);


typedef void (ws_log_writer_free_data_t)(void *user_data);


WS_DLL_PUBLIC
void ws_log_default_writer(const char *message,
                                   enum ws_log_domain domain,
                                   enum ws_log_level level,
                                   void *user_data);


/** Convert a numerical level to its string representation. */
WS_DLL_PUBLIC
const char *ws_log_level_to_string(enum ws_log_level level);


/** Convert a numerical domain to its string representation. */
WS_DLL_PUBLIC
const char *ws_log_domain_to_string(enum ws_log_domain domain);


/** Checks if the active log level would discard a message for the given
 * log domain.
 *
 * Returns TRUE if a message will be discarded for the domain/log_level combo.
 */
WS_DLL_PUBLIC
gboolean ws_log_level_is_active(enum ws_log_level level);


/** Return the currently active log level. */
WS_DLL_PUBLIC
enum ws_log_level ws_log_get_level(void);


/** Set the actice log level. Returns the same value (the active level). */
WS_DLL_PUBLIC
enum ws_log_level ws_log_set_level(enum ws_log_level log_level);


/** Set the actice log level from a string.
 *
 * String levels are "error", "critical", "warning", "message", "info" and
 * "debug" (case insensitive).
 * Returns the new log level or WS_LOG_LEVEL NONE if the string representation
 * is invalid.
 */
WS_DLL_PUBLIC
enum ws_log_level ws_log_set_level_str(const char *str_level);


/** Set the active log level from an argv vector.
 *
 * Will search the arv for the option parameter "--log-level=<string>".
 * If it finds the parameter and the string is valid sets the log level and
 * returns NULL (success). Othwerise returns the invalid option argument after '='.
 */
WS_DLL_PUBLIC
const char *ws_log_set_level_args(int *argcp, char **argv);


/** Initializes the logging code.
 *
 * Must be called at startup before using the log API. If provided the
 * ws_log_writer_t pointer will be used to write every message. If the writer
 * is NULL the default log writer is used.
 */
WS_DLL_PUBLIC
void ws_log_init(ws_log_writer_t *writer);


/** Initializes the logging code.
 *
 * Can be used instead of wslog_init(). Takes an extra user data pointer. This
 * pointer is passed to the writer with each invocation. If a free function
 * is passed it will be called with user_data when the program terminates.
 */
WS_DLL_PUBLIC
void ws_log_init_with_data(ws_log_writer_t *writer, void *user_data,
                              ws_log_writer_free_data_t *free_user_data);


/** This function is called to output a message to the log.
 *
 * Takes a format string and a variable number of arguments.
 */
WS_DLL_PUBLIC
void ws_log(enum ws_log_domain domain, enum ws_log_level level,
                    const char *format, ...) G_GNUC_PRINTF(3,4);

/** This function is called to output a message to the log.
 *
 * Takes a format string and a 'va_list'.
 */
WS_DLL_PUBLIC
void ws_logv(enum ws_log_domain domain, enum ws_log_level level,
                    const char *format, va_list ap);


/** This function is called to output a message to the log.
 *
 * In addition to the message this function accepts file/line/function
 * information. 'func' may be NULL.
 */
WS_DLL_PUBLIC
void ws_log_full(enum ws_log_domain domain, enum ws_log_level level,
                    const char *file, int line, const char *func,
                    const char *format, ...) G_GNUC_PRINTF(6,7);


#define _LOG_FULL(level, ...) ws_log_full(WS_LOG_DOMAIN, level,  \
                                   __FILE__, __LINE__, G_STRFUNC, __VA_ARGS__)

/** Logs with "error" level.
 *
 * Accepts a format string and includes the file and function name.
 *
 * "error" is always fatal and terminates the program with a coredump.
 */
#define ws_error(...)    _LOG_FULL(LOG_LEVEL_ERROR, __VA_ARGS__)

/** Logs with "critical" level.
 *
 * Accepts a format string and includes the file and function name.
 */
#define ws_critical(...) _LOG_FULL(LOG_LEVEL_CRITICAL, __VA_ARGS__)

/** Logs with "warning" level.
 *
 * Accepts a format string and includes the file and function name.
 */
#define ws_warning(...)  _LOG_FULL(LOG_LEVEL_WARNING, __VA_ARGS__)

/** Logs with "message" level.
 *
 * Accepts a format string and includes the file and function name.
 */
#define ws_message(...)  _LOG_FULL(LOG_LEVEL_MESSAGE, __VA_ARGS__)

/** Logs with "info" level.
 *
 * Accepts a format string and includes the file and function name.
 */
#define ws_info(...)     _LOG_FULL(LOG_LEVEL_INFO, __VA_ARGS__)

/** Logs with "debug" level.
 *
 * Accepts a format string and includes the file and function name.
 */
#ifndef WS_DISABLE_DEBUG
#define ws_debug(...)    _LOG_FULL(LOG_LEVEL_DEBUG, __VA_ARGS__)
#else
/* This avoids -Wunused warnings for variables referenced by ws_debug()
 * only. The compiler will optimize it away. */
#define ws_debug(...) \
          G_STMT_START { \
               if (0) _LOG_FULL(LOG_LEVEL_DEBUG, __VA_ARGS__); \
          } G_STMT_END
#endif


/** Define an auxilliary file pointer where messages should be written.
 *
 * This file, if set, functions in addition to the registered log writer.
 */
WS_DLL_PUBLIC
void ws_log_add_custom_file(FILE *fp);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSLOG_H__ */
