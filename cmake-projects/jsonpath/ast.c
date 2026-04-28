/*
 * Copyright (C) 2013-2014 Jo-Philipp Wich <jo@mein.io>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "ast.h"
#include "lexer.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <libubox/utils.h>

struct jp_opcode *
jp_alloc_op(struct jp_state *s, int type, int num, char *str, ...)
{
	va_list ap;
	char *ptr;
	struct jp_opcode *newop, *child;

	newop = calloc_a(sizeof(*newop),
	                 str ? &ptr : NULL, str ? strlen(str) + 1 : 0);

	if (!newop)
	{
		fprintf(stderr, "Out of memory\n");
		exit(127);
	}

	newop->type = type;
	newop->num = num;

	if (str)
		newop->str = strcpy(ptr, str);

	va_start(ap, str);

	while ((child = va_arg(ap, void *)) != NULL)
		if (!newop->down)
			newop->down = child;
		else
			append_op(newop->down, child);

	va_end(ap);

	newop->next = s->pool;
	s->pool = newop;

	return newop;
}

void
jp_free(struct jp_state *s)
{
	struct jp_opcode *op, *tmp;

	for (op = s->pool; op;)
	{
		tmp = op->next;
		free(op);
		op = tmp;
	}

	free(s);
}

struct jp_state *
jp_parse(const char *expr)
{
	struct jp_state *s;
	struct jp_opcode *op;
	const char *ptr = expr;
	void *pParser;
	int len = strlen(expr);
	int mlen = 0;

	s = calloc(1, sizeof(*s));

	if (!s)
		return NULL;

	pParser = ParseAlloc(malloc);

	if (!pParser)
		return NULL;

	while (len > 0)
	{
		op = jp_get_token(s, ptr, &mlen);

		if (mlen < 0)
		{
			s->error_code = mlen;
			goto out;
		}

		if (op)
			Parse(pParser, op->type, op, s);

		len -= mlen;
		ptr += mlen;

		s->off += mlen;
	}

	Parse(pParser, 0, NULL, s);

out:
	ParseFree(pParser, free);

	return s;
}
