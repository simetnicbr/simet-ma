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

#include "parser.h"
#include "matcher.h"


static struct json_object *
jp_match_next(struct jp_opcode *ptr,
              struct json_object *root, struct json_object *cur,
              jp_match_cb_t cb, void *priv);

static bool
jp_json_to_op(struct json_object *obj, struct jp_opcode *op)
{
	switch (json_object_get_type(obj))
	{
	case json_type_boolean:
		op->type = T_BOOL;
		op->num = json_object_get_boolean(obj);
		return true;

	case json_type_int:
		op->type = T_NUMBER;
		op->num = json_object_get_int(obj);
		return true;

	case json_type_string:
		op->type = T_STRING;
		op->str = (char *)json_object_get_string(obj);
		return true;

	default:
		return false;
	}
}

static bool
jp_resolve(struct json_object *root, struct json_object *cur,
           struct jp_opcode *op, struct jp_opcode *res)
{
	struct json_object *val;

	switch (op->type)
	{
	case T_THIS:
		val = jp_match(op, cur, NULL, NULL);

		if (val)
			return jp_json_to_op(val, res);

		return false;

	case T_ROOT:
		val = jp_match(op, root, NULL, NULL);

		if (val)
			return jp_json_to_op(val, res);

		return false;

	default:
		*res = *op;
		return true;
	}
}

static bool
jp_cmp(struct jp_opcode *op, struct json_object *root, struct json_object *cur)
{
	int delta;
	struct jp_opcode left, right;

	if (!jp_resolve(root, cur, op->down, &left) ||
        !jp_resolve(root, cur, op->down->sibling, &right))
		return false;

	if (left.type != right.type)
		return false;

	switch (left.type)
	{
	case T_BOOL:
	case T_NUMBER:
		delta = left.num - right.num;
		break;

	case T_STRING:
		delta = strcmp(left.str, right.str);
		break;

	default:
		return false;
	}

	switch (op->type)
	{
	case T_EQ:
		return (delta == 0);

	case T_LT:
		return (delta < 0);

	case T_LE:
		return (delta <= 0);

	case T_GT:
		return (delta > 0);

	case T_GE:
		return (delta >= 0);

	case T_NE:
		return (delta != 0);

	default:
		return false;
	}
}

static bool
jp_regmatch(struct jp_opcode *op, struct json_object *root, struct json_object *cur)
{
	struct jp_opcode left, right;
	char lbuf[22], rbuf[22], *lval, *rval;
	int err, rflags = REG_NOSUB | REG_NEWLINE;
	regex_t preg;


	if (!jp_resolve(root, cur, op->down, &left) ||
	    !jp_resolve(root, cur, op->down->sibling, &right))
		return false;

	if (left.type == T_REGEXP)
	{
		switch (right.type)
		{
		case T_BOOL:
			lval = right.num ? "true" : "false";
			break;

		case T_NUMBER:
			snprintf(lbuf, sizeof(lbuf), "%d", right.num);
			lval = lbuf;
			break;

		case T_STRING:
			lval = right.str;
			break;

		default:
			return false;
		}

		rval = left.str;
		rflags = left.num;
	}
	else
	{
		switch (left.type)
		{
		case T_BOOL:
			lval = left.num ? "true" : "false";
			break;

		case T_NUMBER:
			snprintf(lbuf, sizeof(lbuf), "%d", left.num);
			lval = lbuf;
			break;

		case T_STRING:
			lval = left.str;
			break;

		default:
			return false;
		}

		switch (right.type)
		{
		case T_BOOL:
			rval = right.num ? "true" : "false";
			break;

		case T_NUMBER:
			snprintf(rbuf, sizeof(rbuf), "%d", right.num);
			rval = rbuf;
			break;

		case T_STRING:
			rval = right.str;
			break;

		case T_REGEXP:
			rval = right.str;
			rflags = right.num;
			break;

		default:
			return false;
		}
	}

	if (regcomp(&preg, rval, rflags))
		return false;

	err = regexec(&preg, lval, 0, NULL, 0);

	regfree(&preg);

	return err ? false : true;
}

static bool
jp_expr(struct jp_opcode *op, struct json_object *root, struct json_object *cur,
        int idx, const char *key, jp_match_cb_t cb, void *priv)
{
	struct jp_opcode *sop;

	switch (op->type)
	{
	case T_WILDCARD:
		return true;

	case T_EQ:
	case T_NE:
	case T_LT:
	case T_LE:
	case T_GT:
	case T_GE:
		return jp_cmp(op, root, cur);

	case T_MATCH:
		return jp_regmatch(op, root, cur);

	case T_ROOT:
		return !!jp_match(op, root, NULL, NULL);

	case T_THIS:
		return !!jp_match(op, cur, NULL, NULL);

	case T_NOT:
		return !jp_expr(op->down, root, cur, idx, key, cb, priv);

	case T_AND:
		for (sop = op->down; sop; sop = sop->sibling)
			if (!jp_expr(sop, root, cur, idx, key, cb, priv))
				return false;
		return true;

	case T_OR:
	case T_UNION:
		for (sop = op->down; sop; sop = sop->sibling)
			if (jp_expr(sop, root, cur, idx, key, cb, priv))
				return true;
		return false;

	case T_STRING:
		return (key && !strcmp(op->str, key));

	case T_NUMBER:
		return (idx == op->num);

	default:
		return false;
	}
}

static struct json_object *
jp_match_expr(struct jp_opcode *ptr,
              struct json_object *root, struct json_object *cur,
              jp_match_cb_t cb, void *priv)
{
	int idx, len;
	struct json_object *tmp, *res = NULL;

	switch (json_object_get_type(cur))
	{
	case json_type_object:
		; /* a label can only be part of a statement and a declaration is not a statement */
		json_object_object_foreach(cur, key, val)
		{
			if (jp_expr(ptr, root, val, -1, key, cb, priv))
			{
				tmp = jp_match_next(ptr->sibling, root, val, cb, priv);

				if (tmp && !res)
					res = tmp;
			}
		}

		break;

	case json_type_array:
		len = json_object_array_length(cur);

		for (idx = 0; idx < len; idx++)
		{
			tmp = json_object_array_get_idx(cur, idx);

			if (jp_expr(ptr, root, tmp, idx, NULL, cb, priv))
			{
				tmp = jp_match_next(ptr->sibling, root, tmp, cb, priv);

				if (tmp && !res)
					res = tmp;
			}
		}

		break;

	default:
		break;
	}

	return res;
}

static struct json_object *
jp_match_next(struct jp_opcode *ptr,
              struct json_object *root, struct json_object *cur,
              jp_match_cb_t cb, void *priv)
{
	int idx;
	struct json_object *next = NULL;

	if (!ptr)
	{
		if (cb)
			cb(cur, priv);

		return cur;
	}

	switch (ptr->type)
	{
	case T_STRING:
	case T_LABEL:
		if (json_object_object_get_ex(cur, ptr->str, &next))
			return jp_match_next(ptr->sibling, root, next, cb, priv);

		break;

	case T_NUMBER:
		if (json_object_get_type(cur) == json_type_array)
		{
			idx = ptr->num;

			if (idx < 0)
				idx += json_object_array_length(cur);

			if (idx >= 0)
				next = json_object_array_get_idx(cur, idx);

			if (next)
				return jp_match_next(ptr->sibling, root, next, cb, priv);
		}

		break;

	default:
		return jp_match_expr(ptr, root, cur, cb, priv);
	}

	return NULL;
}

struct json_object *
jp_match(struct jp_opcode *path, json_object *jsobj,
         jp_match_cb_t cb, void *priv)
{
	if (path->type == T_LABEL)
		path = path->down;

	return jp_match_next(path->down, jsobj, jsobj, cb, priv);
}
