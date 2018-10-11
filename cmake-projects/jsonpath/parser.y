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

%token_type {struct jp_opcode *}
%extra_argument {struct jp_state *s}

%left T_AND.
%left T_OR.
%left T_UNION.
%nonassoc T_EQ T_NE T_GT T_GE T_LT T_LE T_MATCH.
%right T_NOT.

%include {
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "ast.h"
#include "lexer.h"
#include "parser.h"

#define alloc_op(type, num, str, ...) \
	jp_alloc_op(s, type, num, str, ##__VA_ARGS__, NULL)

}

%syntax_error {
	int i;

	for (i = 0; i < sizeof(tokennames) / sizeof(tokennames[0]); i++)
		if (yy_find_shift_action(yypParser, (YYCODETYPE)i) < YYNSTATE + YYNRULE)
			s->error_code |= (1 << i);

	s->error_pos = s->off;
}


input ::= expr(A).									{ s->path = A; }

expr(A) ::= T_LABEL(B) T_EQ path(C).				{ A = B; B->down = C; }
expr(A) ::= path(B).								{ A = B; }

path(A) ::= T_ROOT segments(B).						{ A = alloc_op(T_ROOT, 0, NULL, B); }
path(A) ::= T_THIS segments(B).						{ A = alloc_op(T_THIS, 0, NULL, B); }
path(A) ::= T_ROOT(B).								{ A = B; }
path(A) ::= T_THIS(B).								{ A = B; }

segments(A) ::= segments(B) segment(C).				{ A = append_op(B, C); }
segments(A) ::= segment(B).							{ A = B; }

segment(A) ::= T_DOT T_LABEL(B).					{ A = B; }
segment(A) ::= T_DOT T_WILDCARD(B).					{ A = B; }
segment(A) ::= T_BROPEN union_exps(B) T_BRCLOSE.	{ A = B; }

union_exps(A) ::= union_exp(B).						{ A = B->sibling ? alloc_op(T_UNION, 0, NULL, B) : B; }

union_exp(A) ::= union_exp(B) T_UNION or_exps(C).	{ A = append_op(B, C); }
union_exp(A) ::= or_exps(B).						{ A = B; }

or_exps(A) ::= or_exp(B).							{ A = B->sibling ? alloc_op(T_OR, 0, NULL, B) : B; }

or_exp(A) ::= or_exp(B) T_OR and_exps(C).			{ A = append_op(B, C); }
or_exp(A) ::= and_exps(B).							{ A = B; }

and_exps(A) ::= and_exp(B).							{ A = B->sibling ? alloc_op(T_AND, 0, NULL, B) : B; }

and_exp(A) ::= and_exp(B) T_AND cmp_exp(C).			{ A = append_op(B, C); }
and_exp(A) ::= cmp_exp(B).							{ A = B; }

cmp_exp(A) ::= unary_exp(B) T_LT unary_exp(C).		{ A = alloc_op(T_LT, 0, NULL, B, C); }
cmp_exp(A) ::= unary_exp(B) T_LE unary_exp(C).		{ A = alloc_op(T_LE, 0, NULL, B, C); }
cmp_exp(A) ::= unary_exp(B) T_GT unary_exp(C).		{ A = alloc_op(T_GT, 0, NULL, B, C); }
cmp_exp(A) ::= unary_exp(B) T_GE unary_exp(C).		{ A = alloc_op(T_GE, 0, NULL, B, C); }
cmp_exp(A) ::= unary_exp(B) T_EQ unary_exp(C).		{ A = alloc_op(T_EQ, 0, NULL, B, C); }
cmp_exp(A) ::= unary_exp(B) T_NE unary_exp(C).		{ A = alloc_op(T_NE, 0, NULL, B, C); }
cmp_exp(A) ::= unary_exp(B) T_MATCH unary_exp(C).	{ A = alloc_op(T_MATCH, 0, NULL, B, C); }
cmp_exp(A) ::= unary_exp(B).						{ A = B; }

unary_exp(A) ::= T_BOOL(B).							{ A = B; }
unary_exp(A) ::= T_NUMBER(B).						{ A = B; }
unary_exp(A) ::= T_STRING(B).						{ A = B; }
unary_exp(A) ::= T_REGEXP(B).						{ A = B; }
unary_exp(A) ::= T_WILDCARD(B).						{ A = B; }
unary_exp(A) ::= T_POPEN or_exps(B) T_PCLOSE.		{ A = B; }
unary_exp(A) ::= T_NOT unary_exp(B).				{ A = alloc_op(T_NOT, 0, NULL, B); }
unary_exp(A) ::= path(B).							{ A = B; }
