/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "dfvm.h"

#include <ftypes/ftypes.h>
#include <wsutil/ws_assert.h>

dfvm_insn_t*
dfvm_insn_new(dfvm_opcode_t op)
{
	dfvm_insn_t	*insn;

	insn = g_new(dfvm_insn_t, 1);
	insn->op = op;
	insn->arg1 = NULL;
	insn->arg2 = NULL;
	insn->arg3 = NULL;
	insn->arg4 = NULL;
	return insn;
}

static void
dfvm_value_free(dfvm_value_t *v)
{
	switch (v->type) {
		case FVALUE:
			fvalue_free(v->value.fvalue);
			break;
		case DRANGE:
			drange_free(v->value.drange);
			break;
		case PCRE:
			ws_regex_free(v->value.pcre);
			break;
		default:
			/* nothing */
			;
	}
	g_free(v);
}

void
dfvm_insn_free(dfvm_insn_t *insn)
{
	if (insn->arg1) {
		dfvm_value_free(insn->arg1);
	}
	if (insn->arg2) {
		dfvm_value_free(insn->arg2);
	}
	if (insn->arg3) {
		dfvm_value_free(insn->arg3);
	}
	if (insn->arg4) {
		dfvm_value_free(insn->arg4);
	}
	g_free(insn);
}


dfvm_value_t*
dfvm_value_new(dfvm_value_type_t type)
{
	dfvm_value_t	*v;

	v = g_new(dfvm_value_t, 1);
	v->type = type;
	return v;
}

char *
dfvm_value_tostr(dfvm_value_t *v)
{
	char *s, *aux;

	if (!v)
		return NULL;

	switch (v->type) {
		case HFINFO:
			s = ws_strdup(v->value.hfinfo->abbrev);
			break;
		case FVALUE:
			aux = fvalue_to_debug_repr(NULL, v->value.fvalue);
			s = ws_strdup_printf("%s <%s>",
				aux, fvalue_type_name(v->value.fvalue));
			g_free(aux);
			break;
		case DRANGE:
			s = drange_tostr(v->value.drange);
			break;
		case PCRE:
			s = ws_strdup(ws_regex_pattern(v->value.pcre));
			break;
		case REGISTER:
			s = ws_strdup_printf("reg#%u", v->value.numeric);
			break;
		case FUNCTION_DEF:
			s = ws_strdup(v->value.funcdef->name);
			break;
		default:
			s = ws_strdup("FIXME");
	}
	return s;
}

void
dfvm_dump(FILE *f, dfilter_t *df)
{
	int		id, length;
	dfvm_insn_t	*insn;
	dfvm_value_t	*arg1, *arg2, *arg3, *arg4;
	char 		*arg1_str, *arg2_str, *arg3_str, *arg4_str;

	/* First dump the constant initializations */
	fprintf(f, "Constants:\n");
	length = df->consts->len;
	for (id = 0; id < length; id++) {

		insn = g_ptr_array_index(df->consts, id);
		arg1 = insn->arg1;
		arg2 = insn->arg2;
		arg1_str = dfvm_value_tostr(arg1);
		arg2_str = dfvm_value_tostr(arg2);

		switch (insn->op) {
			case PUT_FVALUE:
				fprintf(f, "%05d PUT_FVALUE\t%s -> %s\n",
					id, arg1_str, arg2_str);
				break;
			case PUT_PCRE:
				fprintf(f, "%05d PUT_PCRE  \t%s -> %s\n",
					id, arg1_str, arg2_str);
				break;
			case CHECK_EXISTS:
			case READ_TREE:
			case CALL_FUNCTION:
			case MK_RANGE:
			case ALL_EQ:
			case ANY_EQ:
			case ALL_NE:
			case ANY_NE:
			case ANY_GT:
			case ANY_GE:
			case ANY_LT:
			case ANY_LE:
			case ANY_BITWISE_AND:
			case ANY_CONTAINS:
			case ANY_MATCHES:
			case ANY_IN_RANGE:
			case NOT:
			case RETURN:
			case IF_TRUE_GOTO:
			case IF_FALSE_GOTO:
				ws_assert_not_reached();
				break;
		}

		g_free(arg1_str);
		g_free(arg2_str);
	}

	fprintf(f, "\nInstructions:\n");
	/* Now dump the operations */
	length = df->insns->len;
	for (id = 0; id < length; id++) {

		insn = g_ptr_array_index(df->insns, id);
		arg1 = insn->arg1;
		arg2 = insn->arg2;
		arg3 = insn->arg3;
		arg4 = insn->arg4;
		arg1_str = dfvm_value_tostr(arg1);
		arg2_str = dfvm_value_tostr(arg2);
		arg3_str = dfvm_value_tostr(arg3);
		arg4_str = dfvm_value_tostr(arg4);

		switch (insn->op) {
			case CHECK_EXISTS:
				fprintf(f, "%05d CHECK_EXISTS\t%s\n",
					id, arg1_str);
				break;

			case READ_TREE:
				fprintf(f, "%05d READ_TREE\t\t%s -> %s\n",
					id, arg1_str, arg2_str);
				break;

			case CALL_FUNCTION:
				fprintf(f, "%05d CALL_FUNCTION\t%s(",
					id, arg1_str);
				if (arg3_str) {
					fprintf(f, "%s", arg3_str);
				}
				if (arg4_str) {
					fprintf(f, ", %s", arg4_str);
				}
				fprintf(f, ") -> %s\n", arg2_str);
				break;

			case MK_RANGE:
				arg3 = insn->arg3;
				fprintf(f, "%05d MK_RANGE\t\t%s[%s] -> %s\n",
					id, arg1_str, arg2_str, arg3_str);
				break;

			case ALL_EQ:
				fprintf(f, "%05d ALL_EQ\t\t%s === %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_EQ:
				fprintf(f, "%05d ANY_EQ\t\t%s == %s\n",
					id, arg1_str, arg2_str);
				break;

			case ALL_NE:
				fprintf(f, "%05d ALL_NE\t\t%s != %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_NE:
				fprintf(f, "%05d ANY_NE\t\t%s !== %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_GT:
				fprintf(f, "%05d ANY_GT\t\t%s > %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_GE:
				fprintf(f, "%05d ANY_GE\t\t%s >= %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_LT:
				fprintf(f, "%05d ANY_LT\t\t%s < %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_LE:
				fprintf(f, "%05d ANY_LE\t\t%s <= %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_BITWISE_AND:
				fprintf(f, "%05d ANY_BITWISE_AND\t%s & %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_CONTAINS:
				fprintf(f, "%05d ANY_CONTAINS\t%s contains %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_MATCHES:
				fprintf(f, "%05d ANY_MATCHES\t%s matches %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_IN_RANGE:
				fprintf(f, "%05d ANY_IN_RANGE\t%s in { %s .. %s }\n",
					id, arg1_str, arg2_str, arg3_str);
				break;

			case NOT:
				fprintf(f, "%05d NOT\n", id);
				break;

			case RETURN:
				fprintf(f, "%05d RETURN\n", id);
				break;

			case IF_TRUE_GOTO:
				fprintf(f, "%05d IF_TRUE_GOTO\t%u\n",
						id, arg1->value.numeric);
				break;

			case IF_FALSE_GOTO:
				fprintf(f, "%05d IF_FALSE_GOTO\t%u\n",
						id, arg1->value.numeric);
				break;

			case PUT_FVALUE:
			case PUT_PCRE:
				/* We already dumped these */
				ws_assert_not_reached();
				break;
		}

		g_free(arg1_str);
		g_free(arg2_str);
		g_free(arg3_str);
		g_free(arg4_str);
	}
}

/* Reads a field from the proto_tree and loads the fvalues into a register,
 * if that field has not already been read. */
static gboolean
read_tree(dfilter_t *df, proto_tree *tree,
				dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	GPtrArray	*finfos;
	field_info	*finfo;
	int		i, len;
	GSList		*fvalues = NULL;
	gboolean	found_something = FALSE;

	header_field_info *hfinfo = arg1->value.hfinfo;
	int reg = arg2->value.numeric;

	/* Already loaded in this run of the dfilter? */
	if (df->attempted_load[reg]) {
		if (df->registers[reg]) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}

	df->attempted_load[reg] = TRUE;

	while (hfinfo) {
		finfos = proto_get_finfo_ptr_array(tree, hfinfo->id);
		if ((finfos == NULL) || (g_ptr_array_len(finfos) == 0)) {
			hfinfo = hfinfo->same_name_next;
			continue;
		}
		else {
			found_something = TRUE;
		}

		len = finfos->len;
		for (i = 0; i < len; i++) {
			finfo = g_ptr_array_index(finfos, i);
			fvalues = g_slist_prepend(fvalues, &finfo->value);
		}

		hfinfo = hfinfo->same_name_next;
	}

	if (!found_something) {
		return FALSE;
	}

	df->registers[reg] = fvalues;
	// These values are referenced only, do not try to free it later.
	df->owns_memory[reg] = FALSE;
	return TRUE;
}


/* Put a constant value in a register. These will not be cleared by
 * free_register_overhead. */
static gboolean
put_fvalue(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	fvalue_t *fv = arg1->value.fvalue;
	int reg = arg2->value.numeric;

	df->registers[reg] = g_slist_prepend(NULL, fv);
	df->owns_memory[reg] = FALSE;
	return TRUE;
}

/* Put a constant PCRE in a register. These will not be cleared by
 * free_register_overhead. */
static gboolean
put_pcre(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	ws_regex_t *pcre = arg1->value.pcre;
	int reg = arg2->value.numeric;

	df->registers[reg] = g_slist_prepend(NULL, pcre);
	df->owns_memory[reg] = FALSE;
	return TRUE;
}

enum match_how {
	MATCH_ANY,
	MATCH_ALL
};

typedef gboolean (*DFVMCompareFunc)(const fvalue_t*, const fvalue_t*);

static gboolean
cmp_test(enum match_how how, DFVMCompareFunc match_func,
					GSList *reg1, GSList *reg2)
{
	GSList *list_a, *list_b;
	gboolean want_all = (how == MATCH_ALL);
	gboolean want_any = (how == MATCH_ANY);
	gboolean have_match;

	list_a = reg1;

	while (list_a) {
		list_b = reg2;
		while (list_b) {
			have_match = match_func(list_a->data, list_b->data);
			if (want_all && !have_match) {
				return FALSE;
			}
			else if (want_any && have_match) {
				return TRUE;
			}
			list_b = g_slist_next(list_b);
		}
		list_a = g_slist_next(list_a);
	}
	/* want_all || !want_any */
	return want_all;
}

/* cmp(A) <=> cmp(a1) OR cmp(a2) OR cmp(a3) OR ... */
static inline gboolean
any_test(dfilter_t *df, DFVMCompareFunc cmp,
				dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	GSList *reg1 = df->registers[arg1->value.numeric];
	GSList *reg2 = df->registers[arg2->value.numeric];

	return cmp_test(MATCH_ANY, cmp, reg1, reg2);
}

/* cmp(A) <=> cmp(a1) AND cmp(a2) AND cmp(a3) AND ... */
static inline gboolean
all_test(dfilter_t *df, DFVMCompareFunc cmp,
				dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	GSList *reg1 = df->registers[arg1->value.numeric];
	GSList *reg2 = df->registers[arg2->value.numeric];

	return cmp_test(MATCH_ALL, cmp, reg1, reg2);
}

static gboolean
any_matches(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	GSList *reg1 = df->registers[arg1->value.numeric];
	GSList *reg2 = df->registers[arg2->value.numeric];
	GSList *list_a, *list_b;

	list_a = reg1;

	while (list_a) {
		list_b = reg2;
		while (list_b) {
			if (fvalue_matches(list_a->data, list_b->data)) {
				return TRUE;
			}
			list_b = g_slist_next(list_b);
		}
		list_a = g_slist_next(list_a);
	}
	return FALSE;
}

static gboolean
any_in_range(dfilter_t *df, dfvm_value_t *arg1,
				dfvm_value_t *arg_low, dfvm_value_t *arg_high)
{
	GSList *list1, *list_low, *list_high;
	fvalue_t *low, *high, *value;

	list1 = df->registers[arg1->value.numeric];
	list_low = df->registers[arg_low->value.numeric];
	list_high = df->registers[arg_high->value.numeric];

	/* The first register contains the values associated with a field, the
	 * second and third arguments are expected to be a single value for the
	 * lower and upper bound respectively. These cannot be fields and thus
	 * the list length MUST be one. This should have been enforced by
	 * grammar.lemon.
	 */
	ws_assert(list_low && !g_slist_next(list_low));
	ws_assert(list_high && !g_slist_next(list_high));
	low = list_low->data;
	high = list_high->data;

	while (list1) {
		value = list1->data;
		if (fvalue_ge(value, low) && fvalue_le(value, high)) {
			return TRUE;
		}
		list1 = g_slist_next(list1);
	}
	return FALSE;
}


static void
free_owned_register(gpointer data, gpointer user_data _U_)
{
	fvalue_t *value = (fvalue_t *)data;
	fvalue_free(value);
}

/* Clear registers that were populated during evaluation (leaving constants
 * intact). If we created the values, then these will be freed as well. */
static void
free_register_overhead(dfilter_t* df)
{
	guint i;

	for (i = 0; i < df->num_registers; i++) {
		df->attempted_load[i] = FALSE;
		if (df->registers[i]) {
			if (df->owns_memory[i]) {
				g_slist_foreach(df->registers[i], free_owned_register, NULL);
				df->owns_memory[i] = FALSE;
			}
			g_slist_free(df->registers[i]);
			df->registers[i] = NULL;
		}
	}
}

/* Takes the list of fvalue_t's in a register, uses fvalue_slice()
 * to make a new list of fvalue_t's (which are ranges, or byte-slices),
 * and puts the new list into a new register. */
static void
mk_range(dfilter_t *df, dfvm_value_t *from_arg, dfvm_value_t *to_arg,
						dfvm_value_t *drange_arg)
{
	GSList		*from_list, *to_list;
	fvalue_t	*old_fv, *new_fv;

	to_list = NULL;
	from_list = df->registers[from_arg->value.numeric];
	drange_t *drange = drange_arg->value.drange;

	while (from_list) {
		old_fv = from_list->data;
		new_fv = fvalue_slice(old_fv, drange);
		/* Assert here because semcheck.c should have
		 * already caught the cases in which a slice
		 * cannot be made. */
		ws_assert(new_fv);
		to_list = g_slist_prepend(to_list, new_fv);

		from_list = g_slist_next(from_list);
	}

	df->registers[to_arg->value.numeric] = to_list;
	df->owns_memory[to_arg->value.numeric] = TRUE;
}

static gboolean
call_function(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *arg2,
				dfvm_value_t *arg3, dfvm_value_t *arg4)
{
	df_func_def_t *funcdef;
	GSList *param1 = NULL;
	GSList *param2 = NULL;
	GSList *retval = NULL;
	gboolean accum;

	funcdef = arg1->value.funcdef;
	if (arg3) {
		param1 = df->registers[arg3->value.numeric];
	}
	if (arg4) {
		param2 = df->registers[arg4->value.numeric];
	}
	accum = funcdef->function(param1, param2, &retval);

	df->registers[arg2->value.numeric] = retval;
	// functions create a new value, so own it.
	df->owns_memory[arg2->value.numeric] = TRUE;
	return accum;
}

gboolean
dfvm_apply(dfilter_t *df, proto_tree *tree)
{
	int		id, length;
	gboolean	accum = TRUE;
	dfvm_insn_t	*insn;
	dfvm_value_t	*arg1;
	dfvm_value_t	*arg2;
	dfvm_value_t	*arg3 = NULL;
	dfvm_value_t	*arg4 = NULL;
	header_field_info	*hfinfo;

	ws_assert(tree);

	length = df->insns->len;

	for (id = 0; id < length; id++) {

	  AGAIN:
		insn = g_ptr_array_index(df->insns, id);
		arg1 = insn->arg1;
		arg2 = insn->arg2;
		arg3 = insn->arg3;
		arg4 = insn->arg4;

		switch (insn->op) {
			case CHECK_EXISTS:
				hfinfo = arg1->value.hfinfo;
				while(hfinfo) {
					accum = proto_check_for_protocol_or_field(tree,
							hfinfo->id);
					if (accum) {
						break;
					}
					else {
						hfinfo = hfinfo->same_name_next;
					}
				}
				break;

			case READ_TREE:
				accum = read_tree(df, tree, arg1, arg2);
				break;

			case CALL_FUNCTION:
				accum = call_function(df, arg1, arg2, arg3, arg4);
				break;

			case MK_RANGE:
				mk_range(df, arg1, arg2, arg3);
				break;

			case ALL_EQ:
				accum = all_test(df, fvalue_eq, arg1, arg2);
				break;

			case ANY_EQ:
				accum = any_test(df, fvalue_eq, arg1, arg2);
				break;

			case ALL_NE:
				accum = all_test(df, fvalue_ne, arg1, arg2);
				break;

			case ANY_NE:
				accum = any_test(df, fvalue_ne, arg1, arg2);
				break;

			case ANY_GT:
				accum = any_test(df, fvalue_gt, arg1, arg2);
				break;

			case ANY_GE:
				accum = any_test(df, fvalue_ge, arg1, arg2);
				break;

			case ANY_LT:
				accum = any_test(df, fvalue_lt, arg1, arg2);
				break;

			case ANY_LE:
				accum = any_test(df, fvalue_le, arg1, arg2);
				break;

			case ANY_BITWISE_AND:
				accum = any_test(df, fvalue_bitwise_and, arg1, arg2);
				break;

			case ANY_CONTAINS:
				accum = any_test(df, fvalue_contains, arg1, arg2);
				break;

			case ANY_MATCHES:
				accum = any_matches(df, arg1, arg2);
				break;

			case ANY_IN_RANGE:
				accum = any_in_range(df, arg1, arg2, arg3);
				break;

			case NOT:
				accum = !accum;
				break;

			case RETURN:
				free_register_overhead(df);
				return accum;

			case IF_TRUE_GOTO:
				if (accum) {
					id = arg1->value.numeric;
					goto AGAIN;
				}
				break;

			case IF_FALSE_GOTO:
				if (!accum) {
					id = arg1->value.numeric;
					goto AGAIN;
				}
				break;

			case PUT_FVALUE:
			case PUT_PCRE:
				/* These were handled in the constants initialization */
				ws_assert_not_reached();
				break;
		}
	}

	ws_assert_not_reached();
}

void
dfvm_init_const(dfilter_t *df)
{
	int		id, length;
	dfvm_insn_t	*insn;
	dfvm_value_t	*arg1;
	dfvm_value_t	*arg2;

	length = df->consts->len;

	for (id = 0; id < length; id++) {

		insn = g_ptr_array_index(df->consts, id);
		arg1 = insn->arg1;
		arg2 = insn->arg2;

		switch (insn->op) {
			case PUT_FVALUE:
				put_fvalue(df, arg1, arg2);
				break;
			case PUT_PCRE:
				put_pcre(df, arg1, arg2);
				break;
			case CHECK_EXISTS:
			case READ_TREE:
			case CALL_FUNCTION:
			case MK_RANGE:
			case ALL_EQ:
			case ANY_EQ:
			case ALL_NE:
			case ANY_NE:
			case ANY_GT:
			case ANY_GE:
			case ANY_LT:
			case ANY_LE:
			case ANY_BITWISE_AND:
			case ANY_CONTAINS:
			case ANY_MATCHES:
			case ANY_IN_RANGE:
			case NOT:
			case RETURN:
			case IF_TRUE_GOTO:
			case IF_FALSE_GOTO:
				ws_assert_not_reached();
				break;
		}
	}
}

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
