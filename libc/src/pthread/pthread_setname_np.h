//===-- Implementation header for pthread_setname_np function ---*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SRC_PTHREAD_PTHREAD_SETNAME_NP_H
#define LLVM_LIBC_SRC_PTHREAD_PTHREAD_SETNAME_NP_H

#include <pthread.h>

namespace LIBC_NAMESPACE {

int pthread_setname_np(pthread_t, const char *name);

} // namespace LIBC_NAMESPACE

#endif // LLVM_LIBC_SRC_PTHREAD_PTHREAD_SETNAME_NP_H
