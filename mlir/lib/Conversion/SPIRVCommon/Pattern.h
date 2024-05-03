//===- Pattern.h - SPIRV Common Conversion Patterns -----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef MLIR_CONVERSION_SPIRVCOMMON_PATTERN_H
#define MLIR_CONVERSION_SPIRVCOMMON_PATTERN_H

#include "mlir/Dialect/SPIRV/IR/SPIRVOpTraits.h"
#include "mlir/IR/TypeUtilities.h"
#include "mlir/Transforms/DialectConversion.h"
#include "llvm/Support/FormatVariadic.h"

namespace mlir {
namespace spirv {

/// Converts elementwise unary, binary and ternary standard operations to SPIR-V
/// operations.
template <typename Op, typename SPIRVOp>
struct ElementwiseOpPattern : public OpConversionPattern<Op> {
  using OpConversionPattern<Op>::OpConversionPattern;

  LogicalResult
  matchAndRewrite(Op op, typename Op::Adaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    assert(adaptor.getOperands().size() <= 3);
    Type dstType = this->getTypeConverter()->convertType(op.getType());
    if (!dstType) {
      return rewriter.notifyMatchFailure(
          op->getLoc(),
          llvm::formatv("failed to convert type {0} for SPIR-V", op.getType()));
    }

    if (SPIRVOp::template hasTrait<OpTrait::spirv::UnsignedOp>() &&
        !getElementTypeOrSelf(op.getType()).isIndex() &&
        dstType != op.getType()) {
      op.dump();
      return op.emitError("bitwidth emulation is not implemented yet on "
                          "unsigned op pattern version");
    }
    rewriter.template replaceOpWithNewOp<SPIRVOp>(op, dstType,
                                                  adaptor.getOperands());
    return success();
  }
};

} // namespace spirv
} // namespace mlir

#endif // MLIR_CONVERSION_SPIRVCOMMON_PATTERN_H
