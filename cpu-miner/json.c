#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "json.h"

typedef struct {
    const char *s;
} parser_t;

static jval_t *parse_value(parser_t *p);

static void skip_ws(parser_t *p)
{
    while (*p->s == ' ' || *p->s == '\t' || *p->s == '\r' || *p->s == '\n')
        p->s++;
}

static jval_t *jnew(jtype_t t)
{
    jval_t *v = calloc(1, sizeof *v);
    if (v)
        v->type = t;
    return v;
}

void json_free(jval_t *v)
{
    if (!v)
        return;
    free(v->str);
    for (int i = 0; i < v->n; i++) {
        json_free(v->items ? v->items[i] : NULL);
        if (v->keys)
            free(v->keys[i]);
    }
    free(v->items);
    free(v->keys);
    free(v);
}

static char *parse_string_raw(parser_t *p)
{
    if (*p->s != '"')
        return NULL;
    p->s++;

    size_t cap = 32, len = 0;
    char *out = malloc(cap);
    if (!out)
        return NULL;

    while (*p->s && *p->s != '"') {
        char c = *p->s;
        if (c == '\\') {
            p->s++;
            switch (*p->s) {
            case '"': c = '"'; break;
            case '\\': c = '\\'; break;
            case '/': c = '/'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'u': {
                unsigned int cp = 0;
                for (int i = 1; i <= 4; i++) {
                    char h = p->s[i];
                    int d = (h >= '0' && h <= '9') ? h - '0' :
                            (h >= 'a' && h <= 'f') ? h - 'a' + 10 :
                            (h >= 'A' && h <= 'F') ? h - 'A' + 10 : -1;
                    if (d < 0) {
                        free(out);
                        return NULL;
                    }
                    cp = cp * 16 + (unsigned int)d;
                }
                p->s += 4;
                c = cp < 0x80 ? (char)cp : '?';
                break;
            }
            default:
                free(out);
                return NULL;
            }
        }
        if (len + 2 > cap) {
            cap *= 2;
            char *n = realloc(out, cap);
            if (!n) {
                free(out);
                return NULL;
            }
            out = n;
        }
        out[len++] = c;
        p->s++;
    }
    if (*p->s != '"') {
        free(out);
        return NULL;
    }
    p->s++;
    out[len] = '\0';
    return out;
}

static int append_item(jval_t *v, char *key, jval_t *item)
{
    jval_t **ni = realloc(v->items, (size_t)(v->n + 1) * sizeof *ni);
    if (!ni)
        return -1;
    v->items = ni;
    if (v->type == J_OBJ) {
        char **nk = realloc(v->keys, (size_t)(v->n + 1) * sizeof *nk);
        if (!nk)
            return -1;
        v->keys = nk;
        v->keys[v->n] = key;
    }
    v->items[v->n] = item;
    v->n++;
    return 0;
}

static jval_t *parse_container(parser_t *p, jtype_t type)
{
    char open = type == J_ARR ? '[' : '{';
    char close = type == J_ARR ? ']' : '}';

    if (*p->s != open)
        return NULL;
    p->s++;

    jval_t *v = jnew(type);
    if (!v)
        return NULL;

    skip_ws(p);
    if (*p->s == close) {
        p->s++;
        return v;
    }

    for (;;) {
        char *key = NULL;

        skip_ws(p);
        if (type == J_OBJ) {
            key = parse_string_raw(p);
            if (!key)
                goto fail;
            skip_ws(p);
            if (*p->s != ':') {
                free(key);
                goto fail;
            }
            p->s++;
        }
        jval_t *item = parse_value(p);
        if (!item) {
            free(key);
            goto fail;
        }
        if (append_item(v, key, item) < 0) {
            free(key);
            json_free(item);
            goto fail;
        }
        skip_ws(p);
        if (*p->s == ',') {
            p->s++;
            continue;
        }
        if (*p->s == close) {
            p->s++;
            return v;
        }
        goto fail;
    }
fail:
    json_free(v);
    return NULL;
}

static jval_t *parse_value(parser_t *p)
{
    skip_ws(p);
    switch (*p->s) {
    case '{':
        return parse_container(p, J_OBJ);
    case '[':
        return parse_container(p, J_ARR);
    case '"': {
        char *s = parse_string_raw(p);
        if (!s)
            return NULL;
        jval_t *v = jnew(J_STR);
        if (!v) {
            free(s);
            return NULL;
        }
        v->str = s;
        return v;
    }
    case 't':
        if (strncmp(p->s, "true", 4))
            return NULL;
        p->s += 4;
        jval_t *vt = jnew(J_BOOL);
        if (vt)
            vt->num = 1;
        return vt;
    case 'f':
        if (strncmp(p->s, "false", 5))
            return NULL;
        p->s += 5;
        return jnew(J_BOOL);
    case 'n':
        if (strncmp(p->s, "null", 4))
            return NULL;
        p->s += 4;
        return jnew(J_NULL);
    default: {
        char *end;
        double d = strtod(p->s, &end);
        if (end == p->s)
            return NULL;
        p->s = end;
        jval_t *v = jnew(J_NUM);
        if (v)
            v->num = d;
        return v;
    }
    }
}

jval_t *json_parse(const char *s)
{
    parser_t p = { s };
    jval_t *v = parse_value(&p);

    if (!v)
        return NULL;
    skip_ws(&p);
    if (*p.s != '\0') {
        json_free(v);
        return NULL;
    }
    return v;
}

jval_t *json_get(const jval_t *obj, const char *key)
{
    if (!obj || obj->type != J_OBJ)
        return NULL;
    for (int i = 0; i < obj->n; i++)
        if (!strcmp(obj->keys[i], key))
            return obj->items[i];
    return NULL;
}

jval_t *json_idx(const jval_t *arr, int i)
{
    if (!arr || (arr->type != J_ARR && arr->type != J_OBJ))
        return NULL;
    if (i < 0 || i >= arr->n)
        return NULL;
    return arr->items[i];
}

const char *json_get_str(const jval_t *obj, const char *key)
{
    jval_t *v = json_get(obj, key);
    return v && v->type == J_STR ? v->str : NULL;
}

double json_get_num(const jval_t *obj, const char *key, double dflt)
{
    jval_t *v = json_get(obj, key);
    return v && (v->type == J_NUM || v->type == J_BOOL) ? v->num : dflt;
}
