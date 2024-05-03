//===-- Linux implementation of sigfillset --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "src/signal/sigfillset.h"
#include "src/__support/common.h"
#include "src/errno/libc_errno.h"
#include "src/signal/linux/signal_utils.h"

#include <signal.h>

namespace LIBC_NAMESPACE {

LLVM_LIBC_FUNCTION(int, sigfillset, (sigset_t * set)) {
  if (!set) {
    libc_errno = EINVAL;
    return -1;
  }
  *set = full_set();
  return 0;
}

} // namespace LIBC_NAMESPACE
