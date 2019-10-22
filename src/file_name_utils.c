/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/**
 * @copyright 2013 Couchbase, Inc.
 *
 * @author Filipe Manana  <filipe@couchbase.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 **/

#if defined(WIN32) || defined(_WIN32)
# define WINDOWS
# include <io.h>
#else
# include <libgen.h>
#endif

#include "file_name_utils.h"

#include <platform/cb_malloc.h>
#include <string.h>

char *file_basename(const char *path)
{
    char *ret;
#ifdef WINDOWS
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    char fname[_MAX_FNAME];
    char ext[_MAX_EXT];

    _splitpath(path, drive, dir, fname, ext);
#else
    char *fname;

    fname = basename((char *) path);
#endif

    ret = (char *) cb_malloc(strlen(fname) + 1);
    if (ret != NULL) {
        strcpy(ret, fname);
    }

    return ret;
}
