/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/* Reference: http://wiki.apache.org/couchdb/View_collation */

#include "couchstore_config.h"

#include "collate_json.h"
#include <ctype.h>
#include <memory>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <platform/cbassert.h>

static int cmp(int n1, int n2)
{
    return n1 > n2 ? 1 : (n1 < n2 ? -1 : 0);
}

static int dcmp(double n1, double n2)
{
    return n1 > n2 ? 1 : (n1 < n2 ? -1 : 0);
}


/* Types of values, ordered according to CouchDB collation order
   (see view_collation.js tests) */
typedef enum {
    kEndArray,
    kEndObject,
    kComma,
    kColon,
    kNull,
    kFalse,
    kTrue,
    kNumber,
    kString,
    kArray,
    kObject,
    kIllegal
} ValueType;


/* "Raw" ordering is:
   0:number, 1:false, 2:null, 3:true, 4:object, 5:array, 6:string
   (according to view_collation_raw.js) */
static int8_t kRawOrderOfValueType[] = {
    -4, -3, -2, -1,
    2, 1, 3, 0, 6, 5, 4,
    7
};


static ValueType valueTypeOf(char c)
{
    switch (c) {
        case 'n':           return kNull;
        case 'f':           return kFalse;
        case 't':           return kTrue;
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
        case '-':           return kNumber;
        case '"':           return kString;
        case ']':           return kEndArray;
        case '}':           return kEndObject;
        case ',':           return kComma;
        case ':':           return kColon;
        case '[':           return kArray;
        case '{':           return kObject;
        default:
            fprintf(stderr, "CouchStore CollateJSON: Unexpected character '%c' (0x%02x)\n", c, (unsigned char)c);
            return kIllegal;
    }
}


static int digitToInt(int c)
{
    if (isdigit(c))
        return c - '0';
    else if (isxdigit(c))
        return 10 + tolower(c) - 'a';
    else
        return 0;
}


char ConvertJSONEscape(const char **in)
{
    int uc;
    char c = *++(*in);
    switch (c) {
        case 'u': {
            /* \u is a Unicode escape; 4 hex digits follow. */
            const char* digits = *in + 1;
            *in += 4;
            uc = (digitToInt(digits[0]) << 12) | (digitToInt(digits[1]) << 8) |
                     (digitToInt(digits[2]) <<  4) | (digitToInt(digits[3]));
            if (uc > 127)
                fprintf(stderr, "CouchStore CollateJSON: Can't correctly compare \\u%.4s\n", digits);
            return (char)uc;
        }
        case 'b':   return '\b';
        case 'n':   return '\n';
        case 'r':   return '\r';
        case 't':   return '\t';
        default:    return c;
    }
}


static int compareStringsASCII(const char** in1, const char** in2)
{
    const char* str1 = *in1, *str2 = *in2;
    int s;
    while(true) {
        char c1 = *++str1;
        char c2 = *++str2;

        /* If one string ends, the other is greater; if both end,
           they're equal */
        if (c1 == '"') {
            if (c2 == '"')
                break;
            else
                return -1;
        } else if (c2 == '"')
            return 1;

        /* Handle escape sequences: */
        if (c1 == '\\')
            c1 = ConvertJSONEscape(&str1);
        if (c2 == '\\')
            c2 = ConvertJSONEscape(&str2);

        /* Compare the next characters: */
        s = cmp(c1, c2);
        if (s)
            return s;
    }

    /* Strings are equal, so update the positions: */
    *in1 = str1 + 1;
    *in2 = str2 + 1;
    return 0;
}


static const char* createStringFromJSON(const char** in, size_t *length, bool *freeWhenDone)
{
    char* buf;
    char* dst;
    char c;
    /* Scan the JSON string to find its length and whether it contains
       escapes: */
    const char* start = ++*in;
    unsigned escapes = 0;
    const char* str;
    for (str = start; *str != '"'; ++str) {
        if (*str == '\\') {
            ++str;
            if (*str == 'u') {
                escapes += 5;  /* \uxxxx adds 5 bytes */
                str += 4;
            } else
                escapes += 1;
        }
    }
    *in = str + 1;
    *length = str - start;

    *freeWhenDone = false;
    if (escapes > 0) {
        *length -= escapes;
        buf = new char[*length];
        dst = buf;
        for (str = start; (c = *str) != '"'; ++str) {
            if (c == '\\')
                c = ConvertJSONEscape(&str);
            *dst++ = c;
        }
        cb_assert(dst - buf == (int)*length);
        start = buf;
        *freeWhenDone = true;
    }

    return start;
}

static int compareUnicodeSlow(const char* str1, size_t len1,
                              const char* str2, size_t len2)
{
    static std::unique_ptr<UCollator, UCollDeleter> coll;
    UCharIterator iterA, iterB;
    int result;

    UErrorCode status = U_ZERO_ERROR;
    if (!coll) {
        coll.reset(ucol_open("", &status));
        if (U_FAILURE(status)) {
            fprintf(stderr, "CouchStore CollateJSON: Couldn't initialize ICU (%d)\n", (int)status);
            return -1;
        }
    }

    uiter_setUTF8(&iterA, str1, (int)len1);
    uiter_setUTF8(&iterB, str2, (int)len2);

    result = ucol_strcollIter(coll.get(), &iterA, &iterB, &status);

    if (U_FAILURE(status)) {
        fprintf(stderr, "CouchStore CollateJSON: ICU error %d\n", (int)status);
        return -1;
    }

    if (result < 0) {
        return -1;
    } else if (result > 0) {
        return 1;
    }

    return 0;
}

static int convertUTF8toUChar(const char *src, UChar *dst, int len)
{
    static std::unique_ptr<UConverter, UConvDeleter> cnv;
    UErrorCode status;
    UChar *p = dst;
    const char *s = src;

    if (!cnv) {
        status = U_ZERO_ERROR;
        cnv.reset(ucnv_open("UTF-8", &status));
        if (!cnv) {
            fprintf(stderr, "CouchStore CollateJSON: Couldn't initialize ICU (%d)\n", (int)status);
            abort();
        }
    }

    while (len) {
        unsigned char ch = (unsigned char)(*s);
        if ((ch & 0x80)) {
            goto icu_conv;
        }
        *p++ = (UChar)(ch);
        s++;
        len--;
    }

    return p - dst;

icu_conv:
    status = U_ZERO_ERROR;
    ucnv_toUnicode(cnv.get(), &p, p + len, &s, s + len, nullptr, 1, &status);

    if (U_FAILURE(status)) {
        return -1;
    }

    return p - dst;
}

static int compareUnicode(const char* str1, size_t len1,
                          const char* str2, size_t len2)
{
    static std::unique_ptr<UCollator, UCollDeleter> coll;
    UChar *b1;
    UChar *b2;
    int ret1, ret2;
    int result;

    if (len1 == 0 && len2 == 0) {
        return 0;
    } else if (len1 == 0) {
        return -1;
    } else if (len2 == 0) {
        return 1;
    }

    UErrorCode status = U_ZERO_ERROR;
    if (!coll) {
        coll.reset(ucol_open("", &status));
        if (U_FAILURE(status)) {
            fprintf(stderr, "CouchStore CollateJSON: Couldn't initialize ICU (%d)\n", (int)status);
            return -1;
        }
    }

    if (len1 > 256 || len2 > 256) {
        return compareUnicodeSlow(str1, len1, str2, len2);
    }

    b1 = new UChar[len1 * sizeof(UChar)];
    b2 = new UChar[len2 * sizeof(UChar)];
    if (b1 == nullptr || b2 == nullptr) {
        delete[] b1;
        delete[] b2;
        fprintf(stderr, "CouchStore CollateJSON: Couldn't allocate memory\n");
        return -2;
    }

    ret1 = convertUTF8toUChar(str1, b1, len1);
    ret2 = convertUTF8toUChar(str2, b2, len2);

    if (ret1 < 0 || ret2 < 0) {
        /* something went wrong with utf8->utf32 conversion */
        delete[] b1;
        delete[] b2;
        return compareUnicodeSlow(str1, len1, str2, len2);
    }

    result = ucol_strcoll(coll.get(), b1, ret1, b2, ret2);
    delete[] b1;
    delete[] b2;

    if (result < 0) {
        return -1;
    } else if (result > 0) {
        return 1;
    }

    return 0;

}


static int compareStringsUnicode(const char** in1, const char** in2)
{
    size_t len1, len2;
    bool free1, free2;
    const char* str1 = createStringFromJSON(in1, &len1, &free1);
    const char* str2 = createStringFromJSON(in2, &len2, &free2);

    int result = compareUnicode(str1, len1, str2, len2);

    if (free1) {
        delete[] str1;
    }
    if (free2) {
        delete[] str2;
    }
    return result;
}


static double readNumber(const char* start, const char* end, char** endOfNumber) {
    /* First copy the string into a zero-terminated buffer so we can safely
       call strtod: */
    char buf[50];
    char* endInStr;
    double result;
    size_t len;
    char* str;

    cb_assert(end > start);
    len = end - start;
    str = (len < sizeof(buf)) ? buf : new char[len + 1];
    if (!str)
        return 0.0;
    memcpy(str, start, len);
    str[len] = '\0';

    result = strtod(str, &endInStr);
    *endOfNumber = (char*)start + (endInStr - str);
    if (len >= sizeof(buf))
        delete[] str;
    return result;
}


int CollateJSON(const sized_buf *buf1,
                const sized_buf *buf2,
                CollateJSONMode mode)
{
    const char* str1 = buf1->buf;
    const char* str2 = buf2->buf;
    int depth = 0;

    do {
        /* Get the types of the next token in each string: */
        ValueType type1 = valueTypeOf(*str1);
        ValueType type2 = valueTypeOf(*str2);
        /* If types don't match, stop and return their relative ordering: */
        if (type1 != type2) {
            if (mode != kCollateJSON_Raw)
                return cmp(type1, type2);
            else
                return cmp(kRawOrderOfValueType[type1], kRawOrderOfValueType[type2]);

        /* If types match, compare the actual token values: */
        } else switch (type1) {
            case kNull:
            case kTrue:
                str1 += 4;
                str2 += 4;
                break;
            case kFalse:
                str1 += 5;
                str2 += 5;
                break;
            case kNumber: {
                char* next1, *next2;
                int diff;
                if (depth == 0) {
                    /* At depth 0, be careful not to fall off the end of the
                       input, because there won't be any delimiters (']' or
                       '}') after the number! */
                    diff = dcmp( readNumber(str1, buf1->buf + buf1->size, &next1),
                                 readNumber(str2, buf2->buf + buf2->size, &next2) );
                } else {
                    diff = dcmp( strtod(str1, &next1), strtod(str2, &next2) );
                }
                if (diff)
                    return diff; /* Numbers don't match */
                str1 = next1;
                str2 = next2;
                break;
            }
            case kString: {
                int diff;
                if (mode == kCollateJSON_Unicode)
                    diff = compareStringsUnicode(&str1, &str2);
                else
                    diff = compareStringsASCII(&str1, &str2);
                if (diff)
                    return diff; /* Strings don't match */
                break;
            }
            case kArray:
            case kObject:
                ++str1;
                ++str2;
                ++depth;
                break;
            case kEndArray:
            case kEndObject:
                ++str1;
                ++str2;
                --depth;
                break;
            case kComma:
            case kColon:
                ++str1;
                ++str2;
                break;
            case kIllegal:
                return 0;
        }
    /* Keep going as long as we're inside an array or object */
    } while (depth > 0);
    return 0;
}
