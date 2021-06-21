/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2021 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSLOG_H__
#define __WSLOG_H__

#include <ws_log_defs.h>
#include <ws_symbol_export.h>
#include <glib.h>
#include <stdio.h>
#include <stdarg.h>

/*
 * Define the macro WS_LOG_DOMAIN *before* including this header,
 * for example:
 *   #define WS_LOG_DOMAIN LOG_DOMAIN_MAIN
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Callback for registering a log writer. */
typedef void (ws_log_writer_cb)(const char *domain, enum ws_log_level level,
                                   const char *timestamp,
                                   const char *file, int line, const char *func,
                                   const char *user_format, va_list user_ap,
                                   void *user_data);


/** Callback for freeing a user data pointer. */
typedef void (ws_log_writer_free_data_cb)(void *user_data);


WS_DLL_PUBLIC
void ws_log_default_writer(const char *domain, enum ws_log_level level,
                            const char *timestamp,
                            const char *file, int line, const char *func,
                            const char *user_format, va_list user_ap,
                            void *user_data);


/** Convert a numerical level to its string representation. */
WS_DLL_PUBLIC
const char *ws_log_level_to_string(enum ws_log_level level);


/** Checks if a domain and level combination generate output.
 *
 * Returns TRUE if a message will be printed for the domain/log_level combo.
 */
WS_DLL_PUBLIC
gboolean ws_log_msg_is_active(const char *domain, enum ws_log_level level);


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


/** Set a domain filter from a string.
 *
 * Domain filter is a case insensitive list separated by ',' or ';'. Only
 * the domains in the filter will generate output; the others will be muted.
 * Filter expressions can be preceded by '!' to invert the sense of the match.
 * In this case only non-matching domains will generate output.
 */
WS_DLL_PUBLIC
void ws_log_set_domain_filter(const char *domain_filter);


/** Set a debug filter from a string.
 *
 * A debug filter lists all domains that should have debug level output turned
 * on, regardless of the global log level and domain filter.
 */
WS_DLL_PUBLIC
void ws_log_set_debug_filter(const char *str_filter);


/** Set a noisy filter from a string.
 *
 * A noisy filter lists all domains that should have noisy level output turned
 * on, regardless of the global log level and domain filter.
 */
WS_DLL_PUBLIC
void ws_log_set_noisy_filter(const char *str_filter);


/** Set the fatal log level.
 *
 * Sets the log level at which calls to ws_log() will abort the program. The
 * argument can be LOG_LEVEL_CRITICAL or LOG_LEVEL_WARNING. Level
 * LOG_LEVEL_ERROR is always fatal.
 */
WS_DLL_PUBLIC
enum ws_log_level ws_log_set_fatal(enum ws_log_level log_level);


/** Set the fatal log level from a string.
 *
 * Same as ws_log_set_fatal(), but accepts the strings "critical" or "warnings"
 * instead as arguments.
 */
WS_DLL_PUBLIC
enum ws_log_level  ws_log_set_fatal_str(const char *str_level);


/** Parses the command line arguments for log options.
 *
 * Returns zero for no error, non-zero for a bad option value.
 */
WS_DLL_PUBLIC
int ws_log_parse_args(int *argc_ptr, char *argv[], void (*print_err)(const char *, ...));


/** Initializes the logging code.
 *
 * Must be called at startup before using the log API. If provided the
 * ws_log_writer_t pointer will be used to write every message. If the writer
 * is NULL the default log writer is used.
 */
WS_DLL_PUBLIC
void ws_log_init(ws_log_writer_cb *writer);


/** Initializes the logging code.
 *
 * Can be used instead of wslog_init(). Takes an extra user data pointer. This
 * pointer is passed to the writer with each invocation. If a free function
 * is passed it will be called with user_data when the program terminates.
 */
WS_DLL_PUBLIC
void ws_log_init_with_data(ws_log_writer_cb *writer, void *user_data,
                              ws_log_writer_free_data_cb *free_user_data);


/** This function is called to output a message to the log.
 *
 * Takes a format string and a variable number of arguments.
 */
WS_DLL_PUBLIC
void ws_log(const char *domain, enum ws_log_level level,
                    const char *format, ...) G_GNUC_PRINTF(3,4);


/** This function is called to output a message to the log.
 *
 * Takes a format string and a 'va_list'.
 */
WS_DLL_PUBLIC
void ws_logv(const char *domain, enum ws_log_level level,
                    const char *format, va_list ap);


/** This function is called to output a message to the log.
 *
 * In addition to the message this function accepts file/line/function
 * information. 'func' may be NULL.
 */
WS_DLL_PUBLIC
void ws_log_full(const char *domain, enum ws_log_level level,
                    const char *file, int line, const char *func,
                    const char *format, ...) G_GNUC_PRINTF(6,7);


/** This function is called to output a message to the log.
 *
 * In addition to the message this function accepts file/line/function
 * information. 'func' may be NULL.
 */
WS_DLL_PUBLIC
void ws_logv_full(const char *domain, enum ws_log_level level,
                    const char *file, int line, const char *func,
                    const char *format, va_list ap);


#ifdef WS_LOG_DOMAIN
#define _LOG_FULL(level, ...) ws_log_full(WS_LOG_DOMAIN, level,  \
                                   __FILE__, __LINE__, G_STRFUNC, __VA_ARGS__)
#else
#define _LOG_FULL(level, ...) ws_log_full(NULL, level,  \
                                   __FILE__, __LINE__, G_STRFUNC, __VA_ARGS__)
#endif

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

#ifndef WS_DISABLE_DEBUG
#define _LOG_DEBUG(level, ...)   _LOG_FULL(level, __VA_ARGS__)
#else
/*
 * This avoids -Wunused warnings for variables used only with
 * !WS_DISABLE_DEBUG,typically inside a ws_debug() call. The compiler will
 * optimize away the dead execution branch.
 */
#define _LOG_DEBUG(level, ...) \
          G_STMT_START { \
               if (0) _LOG_FULL(level, __VA_ARGS__); \
          } G_STMT_END
#endif

/** Logs with "debug" level.
 *
 * Accepts a format string and includes the file and function name.
 */
#define ws_debug(...)    _LOG_DEBUG(LOG_LEVEL_DEBUG, __VA_ARGS__)

/** Logs with "noisy" level.
 *
 * Accepts a format string and includes the file and function name.
 */
#define ws_noisy(...)    _LOG_DEBUG(LOG_LEVEL_NOISY, __VA_ARGS__)


/** Define an auxilliary file pointer where messages should be written.
 *
 * This file, if set, functions in addition to the registered log writer.
 */
WS_DLL_PUBLIC
void ws_log_add_custom_file(FILE *fp);


WS_DLL_PUBLIC
void ws_log_print_usage(FILE *fp);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSLOG_H__ */
