#ifndef VECPOOL_JSON_H
#define VECPOOL_JSON_H

/* Minimal JSON parser — just enough for single-line stratum messages, no
 * external dependency. Numbers are doubles, \uXXXX escapes outside ASCII
 * decode to '?', which never appears in the hex/id fields we consume. */

typedef enum {
    J_NULL,
    J_BOOL,
    J_NUM,
    J_STR,
    J_ARR,
    J_OBJ
} jtype_t;

typedef struct jval {
    jtype_t type;
    double num;         /* J_NUM, and J_BOOL (0/1) */
    char *str;          /* J_STR */
    struct jval **items; /* J_ARR and J_OBJ values */
    char **keys;        /* J_OBJ keys */
    int n;
} jval_t;

jval_t *json_parse(const char *s);
void json_free(jval_t *v);

/* NULL when missing or wrong container type */
jval_t *json_get(const jval_t *obj, const char *key);
jval_t *json_idx(const jval_t *arr, int i);

/* convenience: NULL/0 when absent or not the expected type */
const char *json_get_str(const jval_t *obj, const char *key);
double json_get_num(const jval_t *obj, const char *key, double dflt);

#endif
