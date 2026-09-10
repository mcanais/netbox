#ifndef _RESULT_H
#define _RESULT_H

#include <stdarg.h>
#include <stdio.h>

typedef enum {
	SUCCESS,
	FAILURE
} res_t;


inline res_t failure(char *fmt, ...) {
	va_list args;
    va_start(args, fmt);
    fprintf(stderr, fmt, args);
    va_end(args);

	return FAILURE;
}

#endif
