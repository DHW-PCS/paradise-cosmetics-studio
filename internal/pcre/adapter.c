#include "pcre2.h"
#include "adapter.h"

int bs_pcre_match(const char *pattern, size_t pattern_len, uint32_t flags,
                  const char *subject, size_t subject_len, int *error, size_t *offset)
{
    pcre2_compile_context *compile_context = pcre2_compile_context_create(NULL);
    if (compile_context == NULL) return -3;
    /* PHP 8.1 enables this option for its lookaround \K compatibility. */
    pcre2_set_compile_extra_options(compile_context, PCRE2_EXTRA_ALLOW_LOOKAROUND_BSK);
    pcre2_code *code = pcre2_compile((PCRE2_SPTR)pattern, pattern_len, flags, error, offset, compile_context);
    pcre2_compile_context_free(compile_context);
    if (code == NULL) return -1;

    pcre2_match_data *data = pcre2_match_data_create_from_pattern(code, NULL);
    pcre2_match_context *context = pcre2_match_context_create(NULL);
    pcre2_jit_stack *stack = pcre2_jit_stack_create(32 * 1024, 192 * 1024, NULL);
    if (data == NULL || context == NULL || stack == NULL) {
        pcre2_jit_stack_free(stack);
        pcre2_match_context_free(context);
        pcre2_match_data_free(data);
        pcre2_code_free(code);
        return -3;
    }

    /* Frozen PHP settings: pcre.backtrack_limit, pcre.recursion_limit and JIT stack. */
    pcre2_set_match_limit(context, 1000000);
    pcre2_set_depth_limit(context, 100000);
    pcre2_jit_stack_assign(context, NULL, stack);
    /* PCRE2 returns unsupported for patterns such as UTF \C; PHP then uses the interpreter. */
    pcre2_jit_compile(code, PCRE2_JIT_COMPLETE);
    int result = pcre2_match(code, (PCRE2_SPTR)subject, subject_len, 0, 0, data, context);
    pcre2_jit_stack_free(stack);
    pcre2_match_context_free(context);
    pcre2_match_data_free(data);
    pcre2_code_free(code);
    *error = result;
    if (result >= 0) return 1;
    return result == PCRE2_ERROR_NOMATCH ? 0 : -2;
}
