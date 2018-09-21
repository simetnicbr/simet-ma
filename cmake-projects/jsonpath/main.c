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

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#ifdef JSONC
	#include <json.h>
#else
	#include <json-c/json.h>
#endif

#include "libubox/list.h"

#include "lexer.h"
#include "parser.h"
#include "matcher.h"


struct match_item {
	struct json_object *jsobj;
	struct list_head list;
};

static void
print_usage(char *app)
{
	printf(
	"== Usage ==\n\n"
	"  # %s [-a] [-i <file> | -s \"json...\"] {-t <pattern> | -e <pattern>}\n"
	"  -q		Quiet, no errors are printed\n"
	"  -h, --help	Print this help\n"
	"  -a		Implicitely treat input as array, useful for JSON logs\n"
	"  -i path	Specify a JSON file to parse\n"
	"  -s \"json\"	Specify a JSON string to parse\n"
	"  -l limit	Specify max number of results to show\n"
	"  -F separator	Specify a field separator when using export\n"
	"  -t <pattern>	Print the type of values matched by pattern\n"
	"  -e <pattern>	Print the values matched by pattern\n"
	"  -e VAR=<pat>	Serialize matched value for shell \"eval\"\n\n"
	"== Patterns ==\n\n"
	"  Patterns are JsonPath: http://goessner.net/articles/JsonPath/\n"
	"  This tool implements $, @, [], * and the union operator ','\n"
	"  plus the usual expressions and literals.\n"
	"  It does not support the recursive child search operator '..' or\n"
	"  the '?()' and '()' filter expressions as those would require a\n"
	"  complete JavaScript engine to support them.\n\n"
	"== Examples ==\n\n"
	"  Display the first IPv4 address on lan:\n"
	"  # ifstatus lan | %s -e '@[\"ipv4-address\"][0].address'\n\n"
	"  Extract the release string from the board information:\n"
	"  # ubus call system board | %s -e '@.release.description'\n\n"
	"  Find all interfaces which are up:\n"
	"  # ubus call network.interface dump | \\\n"
	"  	%s -e '@.interface[@.up=true].interface'\n\n"
	"  Export br-lan traffic counters for shell eval:\n"
	"  # devstatus br-lan | %s -e 'RX=@.statistics.rx_bytes' \\\n"
	"	-e 'TX=@.statistics.tx_bytes'\n",
		app, app, app, app, app);
}

static struct json_object *
parse_json_chunk(struct json_tokener *tok, struct json_object *array,
                 const char *buf, size_t len, enum json_tokener_error *err)
{
	struct json_object *obj = NULL;

	while (len)
	{
		obj = json_tokener_parse_ex(tok, buf, len);
		*err = json_tokener_get_error(tok);

		if (*err == json_tokener_success)
		{
			if (array)
			{
				json_object_array_add(array, obj);
			}
			else
			{
				break;
			}
		}
		else if (*err != json_tokener_continue)
		{
			break;
		}

		buf += tok->char_offset;
		len -= tok->char_offset;
	}

	return obj;
}

static struct json_object *
parse_json(FILE *fd, const char *source, const char **error, bool array_mode)
{
	size_t len;
	char buf[256];
	struct json_object *obj = NULL, *array = NULL;
	struct json_tokener *tok = json_tokener_new();
	enum json_tokener_error err = json_tokener_continue;

	if (!tok)
	{
		*error = "Out of memory";
		return NULL;
	}

	if (array_mode)
	{
		array = json_object_new_array();

		if (!array)
		{
			json_tokener_free(tok);
			*error = "Out of memory";
			return NULL;
		}
	}

	if (source)
	{
		obj = parse_json_chunk(tok, array, source, strlen(source), &err);
	}
	else
	{
		while ((len = fread(buf, 1, sizeof(buf), fd)) > 0)
		{
			obj = parse_json_chunk(tok, array, buf, len, &err);

			if (err == json_tokener_success && !array)
				break;

			if (err != json_tokener_continue)
				break;
		}
	}

	json_tokener_free(tok);

	if (err)
	{
		if (err == json_tokener_continue)
			err = json_tokener_error_parse_eof;

		*error = json_tokener_error_desc(err);
		return NULL;
	}

	return array ? array : obj;
}

static void
print_string(const char *s)
{
	const char *p;

	printf("'");

	for (p = s; *p; p++)
	{
		if (*p == '\'')
			printf("'\"'\"'");
		else
			printf("%c", *p);
	}

	printf("'");
}

static void
print_separator(const char *sep, int *sc, int sl)
{
	if (*sc > 0)
	{
		switch (sep[(*sc - 1) % sl])
		{
		case '"':
			printf("'\"'");
			break;

		case '\'':
			printf("\"'\"");
			break;

		case ' ':
			printf("\\ ");
			break;

		default:
			printf("%c", sep[(*sc - 1) % sl]);
		}
	}

	(*sc)++;
}

static void
export_value(struct list_head *matches, const char *prefix, const char *sep,
             int limit)
{
	int n, len;
	int sc = 0, sl = strlen(sep);
	struct match_item *item;

	if (list_empty(matches))
		return;

	if (prefix)
	{
		printf("export %s=", prefix);

		list_for_each_entry(item, matches, list)
		{
			if (limit-- <= 0)
				break;

			switch (json_object_get_type(item->jsobj))
			{
			case json_type_object:
				; /* a label can only be part of a statement */
				json_object_object_foreach(item->jsobj, key, val)
				{
					if (!val)
						continue;

					print_separator(sep, &sc, sl);
					print_string(key);
				}
				break;

			case json_type_array:
				for (n = 0, len = json_object_array_length(item->jsobj);
				     n < len; n++)
				{
					print_separator(sep, &sc, sl);
					printf("%d", n);
				}
				break;

			case json_type_boolean:
				print_separator(sep, &sc, sl);
				printf("%d", json_object_get_boolean(item->jsobj));
				break;

			case json_type_int:
				print_separator(sep, &sc, sl);
				printf("%" PRId64, json_object_get_int64(item->jsobj));
				break;

			case json_type_double:
				print_separator(sep, &sc, sl);
				printf("%f", json_object_get_double(item->jsobj));
				break;

			case json_type_string:
				print_separator(sep, &sc, sl);
				print_string(json_object_get_string(item->jsobj));
				break;

			case json_type_null:
				break;
			}
		}

		printf("; ");
	}
	else
	{
		list_for_each_entry(item, matches, list)
		{
			if (limit-- <= 0)
				break;

			switch (json_object_get_type(item->jsobj))
			{
			case json_type_object:
			case json_type_array:
			case json_type_boolean:
			case json_type_int:
			case json_type_double:
				printf("%s\n", json_object_to_json_string(item->jsobj));
				break;

			case json_type_string:
				printf("%s\n", json_object_get_string(item->jsobj));
				break;

			case json_type_null:
				break;
			}
		}
	}
}

static void
export_type(struct list_head *matches, const char *prefix, int limit)
{
	bool first = true;
	struct match_item *item;
	const char *types[] = {
		"null",
		"boolean",
		"double",
		"int",
		"object",
		"array",
		"string"
	};

	if (list_empty(matches))
		return;

	if (prefix)
		printf("export %s=", prefix);

	list_for_each_entry(item, matches, list)
	{
		if (!first)
			printf("\\ ");

		if (limit-- <= 0)
			break;

		printf("%s", types[json_object_get_type(item->jsobj)]);
		first = false;
	}

	if (prefix)
		printf("; ");
	else
		printf("\n");
}

static void
match_cb(struct json_object *res, void *priv)
{
	struct list_head *h = priv;
	struct match_item *i = calloc(1, sizeof(*i));

	if (i)
	{
		i->jsobj = res;
		list_add_tail(&i->list, h);
	}
}

static void
print_error(struct jp_state *state, char *expr)
{
	int i;
	bool first = true;

	fprintf(stderr, "Syntax error: ");

	switch (state->error_code)
	{
	case -4:
		fprintf(stderr, "Unexpected character\n");
		break;

	case -3:
		fprintf(stderr, "String or label literal too long\n");
		break;

	case -2:
		fprintf(stderr, "Invalid escape sequence\n");
		break;

	case -1:
		fprintf(stderr, "Unterminated string\n");
		break;

	default:
		for (i = 0; i < sizeof(state->error_code) * 8; i++)
		{
			if (state->error_code & (1 << i))
			{
				fprintf(stderr,
				        first ? "Expecting %s" : " or %s", tokennames[i]);

				first = false;
			}
		}

		fprintf(stderr, "\n");
		break;
	}

	fprintf(stderr, "In expression %s\n", expr);
	fprintf(stderr, "Near here ----");

	for (i = 0; i < state->error_pos; i++)
		fprintf(stderr, "-");

	fprintf(stderr, "^\n");
}

static bool
filter_json(int opt, struct json_object *jsobj, char *expr, const char *sep,
            int limit)
{
	struct jp_state *state;
	const char *prefix = NULL;
	struct list_head matches;
	struct match_item *item, *tmp;
	struct json_object *res = NULL;

	state = jp_parse(expr);

	if (!state)
	{
		fprintf(stderr, "Out of memory\n");
		goto out;
	}
	else if (state->error_code)
	{
		print_error(state, expr);
		goto out;
	}

	INIT_LIST_HEAD(&matches);

	res = jp_match(state->path, jsobj, match_cb, &matches);
	prefix = (state->path->type == T_LABEL) ? state->path->str : NULL;

	switch (opt)
	{
	case 't':
		export_type(&matches, prefix, limit);
		break;

	default:
		export_value(&matches, prefix, sep, limit);
		break;
	}

	list_for_each_entry_safe(item, tmp, &matches, list)
		free(item);

out:
	if (state)
		jp_free(state);

	return !!res;
}

int main(int argc, char **argv)
{
	bool array_mode = false;
	int opt, rv = 0, limit = 0x7FFFFFFF;
	FILE *input = stdin;
	struct json_object *jsobj = NULL;
	const char *jserr = NULL, *source = NULL, *separator = " ";

	if (argc == 1)
	{
		print_usage(argv[0]);
		goto out;
	}

	while ((opt = getopt(argc, argv, "ahi:s:e:t:F:l:q")) != -1)
	{
		switch (opt)
		{
		case 'a':
			array_mode = true;
			break;

		case 'h':
			print_usage(argv[0]);
			goto out;

		case 'i':
			input = fopen(optarg, "r");

			if (!input)
			{
				fprintf(stderr, "Failed to open %s: %s\n",
						optarg, strerror(errno));

				rv = 125;
				goto out;
			}

			break;

		case 's':
			source = optarg;
			break;

		case 'F':
			if (optarg && *optarg)
				separator = optarg;
			break;

		case 'l':
			limit = atoi(optarg);
			break;

		case 't':
		case 'e':
			if (!jsobj)
			{
				jsobj = parse_json(input, source, &jserr, array_mode);

				if (!jsobj)
				{
					fprintf(stderr, "Failed to parse json data: %s\n",
					        jserr);

					rv = 126;
					goto out;
				}
			}

			if (!filter_json(opt, jsobj, optarg, separator, limit))
				rv = 1;

			break;

		case 'q':
			fclose(stderr);
			break;
		}
	}

out:
	if (jsobj)
		json_object_put(jsobj);

	if (input && input != stdin)
		fclose(input);

	return rv;
}
