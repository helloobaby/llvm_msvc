//===-- Implementation header of vfprintf -----------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SRC_STDIO_VFPRINTF_H
#define LLVM_LIBC_SRC_STDIO_VFPRINTF_H

#include <stdarg.h>
#include <stdio.h>

namespace LIBC_NAMESPACE {

int vfprintf(::FILE *__restrict stream, const char *__restrict format,
             va_list vlist);

} // namespace LIBC_NAMESPACE

#endif // LLVM_LIBC_SRC_STDIO_VFPRINTF_H
