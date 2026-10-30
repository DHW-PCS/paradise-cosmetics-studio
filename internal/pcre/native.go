package pcre

/*
#cgo CFLAGS: -I${SRCDIR}/include -DHAVE_CONFIG_H -DPCRE2_CODE_UNIT_WIDTH=8 -DPCRE2_STATIC -DSUPPORT_PCRE2_8 -DSUPPORT_UNICODE -DSUPPORT_JIT -DHAVE_MEMMOVE -DHAVE_STDINT_H -DHAVE_INTTYPES_H -DHAVE_STDLIB_H -DHAVE_STRING_H -DHAVE_LIMITS_H
#cgo darwin linux CFLAGS: -DHAVE_UNISTD_H
#include <stdlib.h>
#include "pcre2.h"
#include "adapter.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func match(pattern, modifiers, subject string) (bool, error) {
	var flags C.uint32_t
	for i := 0; i < len(modifiers); i++ {
		switch modifiers[i] {
		case 'i':
			flags |= C.PCRE2_CASELESS
		case 'm':
			flags |= C.PCRE2_MULTILINE
		case 's':
			flags |= C.PCRE2_DOTALL
		case 'x':
			flags |= C.PCRE2_EXTENDED
		case 'A':
			flags |= C.PCRE2_ANCHORED
		case 'D':
			flags |= C.PCRE2_DOLLAR_ENDONLY
		case 'U':
			flags |= C.PCRE2_UNGREEDY
		case 'u':
			flags |= C.PCRE2_UTF | C.PCRE2_UCP
		case 'J':
			flags |= C.PCRE2_DUPNAMES
		case 'S', 'X', ' ', '\n', '\r': // PHP 8.1 accepts these without a flag.
		default:
			return false, fmt.Errorf("pcre: unknown modifier %q", modifiers[i])
		}
	}
	cp, cs := C.CString(pattern), C.CString(subject)
	defer C.free(unsafe.Pointer(cp))
	defer C.free(unsafe.Pointer(cs))
	var code C.int
	var offset C.size_t
	result := C.bs_pcre_match(cp, C.size_t(len(pattern)), flags, cs, C.size_t(len(subject)), &code, &offset)
	switch result {
	case 1:
		return true, nil
	case 0:
		return false, nil
	case -1:
		return false, fmt.Errorf("pcre: compile failed (%d) at byte %d", int(code), uint64(offset))
	case -2:
		if code >= C.PCRE2_ERROR_UTF8_ERR21 && code <= C.PCRE2_ERROR_UTF8_ERR1 ||
			code == C.PCRE2_ERROR_MATCHLIMIT || code == C.PCRE2_ERROR_DEPTHLIMIT ||
			code == C.PCRE2_ERROR_JIT_STACKLIMIT || code == C.PCRE2_ERROR_HEAPLIMIT ||
			code == C.PCRE2_ERROR_RECURSELOOP {
			return false, &ExecutionError{Code: int(code)}
		}
		return false, fmt.Errorf("pcre: native execution failed (%d)", int(code))
	default:
		return false, fmt.Errorf("pcre: native allocation failed")
	}
}
