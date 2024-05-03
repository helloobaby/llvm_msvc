/*===---- varargs.h - Variable argument handling -------------------------------------===
*
* Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
* See https://llvm.org/LICENSE.txt for license information.
* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*
*===-----------------------------------------------------------------------===
*/
#ifndef __VARARGS_H
#define __VARARGS_H
#ifndef __LLVM_MSVC__PE__
#error "Please use <stdarg.h> instead of <varargs.h>"
#else
#include <varargs_msvc.h>
#endif
#endif
