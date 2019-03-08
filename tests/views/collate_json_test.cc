/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*  Reference: http://wiki.apache.org/couchdb/View_collation */

#include "../src/views/collate_json.h"
#include "../macros.h"
#include "view_tests.h"

#include <platform/cb_malloc.h>
#include <platform/cbassert.h>
#include <stdio.h>
#include <string.h>
#include <unicode/uclean.h>

static int collateStrs(const char* str1, const char* str2, CollateJSONMode mode)
{
    /* Be evil and put numeric garbage past the ends of str1 and str2, to make
       sure it doesn't confuse the numeric parsing in the collator: */
    size_t len1 = strlen(str1), len2 = strlen(str2);
    char *padded1 = (char*)cb_malloc(len1 + 3);
    char *padded2 = (char*)cb_malloc(len2 + 3);
    int ret;
    sized_buf buf1;
    sized_buf buf2;

    cb_assert(padded1);
    cb_assert(padded2);

    strcpy(padded1, str1);
    strcat(padded1, "99");
    strcpy(padded2, str2);
    strcat(padded2, "88");

    buf1.buf = padded1;
    buf1.size = len1;
    buf2.buf = padded2;
    buf2.size = len2;
    ret =  CollateJSON(&buf1, &buf2, mode);
    cb_free(padded1);
    cb_free(padded2);
    return ret;
}


static void testEscape(const char* source, char decoded) {
    const char* pos = source;
    assert_eq(ConvertJSONEscape(&pos), decoded);
    assert_eq((size_t)pos, (size_t)(source + strlen(source) - 1));
}


static void TestCollateConvertEscape(void)
{
    fprintf(stderr, "escapes... ");
    testEscape("\\\\",    '\\');
    testEscape("\\t",     '\t');
    testEscape("\\u0045", 'E');
    testEscape("\\u0001", 1);
    testEscape("\\u0000", 0);
}

static void TestCollateScalars(void)
{
    CollateJSONMode mode = kCollateJSON_Unicode;
    fprintf(stderr, "scalars... ");
    assert_eq(collateStrs("true", "false", mode), 1);
    assert_eq(collateStrs("false", "true", mode), -1);
    assert_eq(collateStrs("null", "17", mode), -1);
    assert_eq(collateStrs("123", "123", mode), 0);
    assert_eq(collateStrs("123", "1", mode), 1);
    assert_eq(collateStrs("123", "0123.0", mode), 0);
    assert_eq(collateStrs("123", "\"123\"", mode), -1);
    assert_eq(collateStrs("\"1234\"", "\"123\"", mode), 1);
    assert_eq(collateStrs("\"1234\"", "\"1235\"", mode), -1);
    assert_eq(collateStrs("\"1234\"", "\"1234\"", mode), 0);
    assert_eq(collateStrs("\"12\\/34\"", "\"12/34\"", mode), 0);
    assert_eq(collateStrs("\"\\/1234\"", "\"/1234\"", mode), 0);
    assert_eq(collateStrs("\"1234\\/\"", "\"1234/\"", mode), 0);
    assert_eq(collateStrs("\"a\"", "\"A\"", mode), -1);
    assert_eq(collateStrs("\"A\"", "\"aa\"", mode), -1);
    assert_eq(collateStrs("\"B\"", "\"aa\"", mode), 1);
}

static void TestCollateASCII(void)
{
    CollateJSONMode mode = kCollateJSON_ASCII;
    fprintf(stderr, "ASCII... ");
    assert_eq(collateStrs("true", "false", mode), 1);
    assert_eq(collateStrs("false", "true", mode), -1);
    assert_eq(collateStrs("null", "17", mode), -1);
    assert_eq(collateStrs("123", "1", mode), 1);
    assert_eq(collateStrs("123", "0123.0", mode), 0);
    assert_eq(collateStrs("123", "\"123\"", mode), -1);
    assert_eq(collateStrs("\"1234\"", "\"123\"", mode), 1);
    assert_eq(collateStrs("\"1234\"", "\"1235\"", mode), -1);
    assert_eq(collateStrs("\"1234\"", "\"1234\"", mode), 0);
    assert_eq(collateStrs("\"12\\/34\"", "\"12/34\"", mode), 0);
    assert_eq(collateStrs("\"\\/1234\"", "\"/1234\"", mode), 0);
    assert_eq(collateStrs("\"1234\\/\"", "\"1234/\"", mode), 0);
    assert_eq(collateStrs("\"A\"", "\"a\"", mode), -1);
    assert_eq(collateStrs("\"B\"", "\"a\"", mode), -1);
}

static void TestCollateRaw(void)
{
    CollateJSONMode mode = kCollateJSON_Raw;
    fprintf(stderr, "raw... ");
    assert_eq(collateStrs("false", "17", mode), 1);
    assert_eq(collateStrs("false", "true", mode), -1);
    assert_eq(collateStrs("null", "true", mode), -1);
    assert_eq(collateStrs("[\"A\"]", "\"A\"", mode), -1);
    assert_eq(collateStrs("\"A\"", "\"a\"", mode), -1);
    assert_eq(collateStrs("[\"b\"]", "[\"b\",\"c\",\"a\"]", mode), -1);
}

static void TestCollateArrays(void)
{
    CollateJSONMode mode = kCollateJSON_Unicode;
    fprintf(stderr, "arrays... ");
    assert_eq(collateStrs("[]", "\"foo\"", mode), 1);
    assert_eq(collateStrs("[]", "[]", mode), 0);
    assert_eq(collateStrs("[true]", "[true]", mode), 0);
    assert_eq(collateStrs("[false]", "[null]", mode), 1);
    assert_eq(collateStrs("[]", "[null]", mode), -1);
    assert_eq(collateStrs("[123]", "[45]", mode), 1);
    assert_eq(collateStrs("[123]", "[45,67]", mode), 1);
    assert_eq(collateStrs("[123.4,\"wow\"]", "[123.40,789]", mode), 1);
}

static void TestCollateNestedArrays(void)
{
    CollateJSONMode mode = kCollateJSON_Unicode;
    fprintf(stderr, "nesting... ");
    assert_eq(collateStrs("[[]]", "[]", mode), 1);
    assert_eq(collateStrs("[1,[2,3],4]", "[1,[2,3.1],4,5,6]", mode), -1);
}

static void TestCollateUnicodeStrings(void)
{
    /* Make sure that TDJSON never creates escape sequences we can't parse.
       That includes "\unnnn" for non-ASCII chars, and "\t", "\b", etc. */
    CollateJSONMode mode = kCollateJSON_Unicode;
    fprintf(stderr, "Unicode... ");
    assert_eq(collateStrs("\"fréd\"", "\"fréd\"", mode), 0);
    assert_eq(collateStrs("\"mip你好\"", "\"mip你好\"", mode), 0);
    assert_eq(collateStrs("\"ømø\"",  "\"omo\"", mode), 1);
    assert_eq(collateStrs("\"\t\"",   "\" \"", mode), -1);
    assert_eq(collateStrs("\"\001\"", "\" \"", mode), -1);
    /* MB-12967 */
    assert_eq(collateStrs("\"法\"", "\"法、\"", mode), -1);
    assert_eq(collateStrs("\"\"", "\"a\"", mode), -1);
    assert_eq(collateStrs("\"a\"", "\"\"", mode), 1);
    assert_eq(collateStrs("\"\"", "\"\"", mode), 0);
}

void test_collate_json(void)
{
    fprintf(stderr, "JSON collation: ");
    TestCollateConvertEscape();
    TestCollateScalars();
    TestCollateASCII();
    TestCollateRaw();
    TestCollateArrays();
    TestCollateNestedArrays();
    TestCollateUnicodeStrings();
    fprintf(stderr, "OK\n");

    /* Invoke cleanup to release all the resources held by ICU */
    u_cleanup();
}
