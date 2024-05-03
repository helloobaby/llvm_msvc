//===-- Implementation header for fchmod ------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SRC_SYS_STAT_FCHMOD_H
#define LLVM_LIBC_SRC_SYS_STAT_FCHMOD_H

#include <sys/stat.h>

namespace LIBC_NAMESPACE {

int fchmod(int fd, mode_t mode);

} // namespace LIBC_NAMESPACE

#endif // LLVM_LIBC_SRC_SYS_STAT_FCHMOD_H
