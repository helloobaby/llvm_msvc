//===- LvlTypeParser.h - `LevelType` parser ----------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "LvlTypeParser.h"
#include "mlir/Dialect/SparseTensor/IR/Enums.h"

using namespace mlir;
using namespace mlir::sparse_tensor;
using namespace mlir::sparse_tensor::ir_detail;

//===----------------------------------------------------------------------===//
#define FAILURE_IF_FAILED(STMT)                                                \
  if (failed(STMT)) {                                                          \
    return failure();                                                          \
  }

// NOTE: this macro assumes `AsmParser parser` and `SMLoc loc` are in scope.
#define ERROR_IF(COND, MSG)                                                    \
  if (COND) {                                                                  \
    return parser.emitError(loc, MSG);                                         \
  }

//===----------------------------------------------------------------------===//
// `LvlTypeParser` implementation.
//===----------------------------------------------------------------------===//

FailureOr<uint8_t> LvlTypeParser::parseLvlType(AsmParser &parser) const {
  StringRef base;
  const auto loc = parser.getCurrentLocation();
  ERROR_IF(failed(parser.parseOptionalKeyword(&base)),
           "expected valid level format (e.g. dense, compressed or singleton)")
  uint8_t properties = 0;

  ParseResult res = parser.parseCommaSeparatedList(
      mlir::OpAsmParser::Delimiter::OptionalParen,
      [&]() -> ParseResult { return parseProperty(parser, &properties); },
      " in level property list");
  FAILURE_IF_FAILED(res)

  // Set the base bit for properties.
  if (base.compare("dense") == 0) {
    properties |= static_cast<uint8_t>(LevelFormat::Dense);
  } else if (base.compare("compressed") == 0) {
    properties |= static_cast<uint8_t>(LevelFormat::Compressed);
  } else if (base.compare("block2_4") == 0) {
    properties |= static_cast<uint8_t>(LevelFormat::TwoOutOfFour);
  } else if (base.compare("loose_compressed") == 0) {
    properties |= static_cast<uint8_t>(LevelFormat::LooseCompressed);
  } else if (base.compare("singleton") == 0) {
    properties |= static_cast<uint8_t>(LevelFormat::Singleton);
  } else {
    parser.emitError(loc, "unknown level format: ") << base;
    return failure();
  }

  ERROR_IF(!isValidLT(static_cast<LevelType>(properties)),
           "invalid level type: level format doesn't support the properties");
  return properties;
}

ParseResult LvlTypeParser::parseProperty(AsmParser &parser,
                                         uint8_t *properties) const {
  StringRef strVal;
  auto loc = parser.getCurrentLocation();
  ERROR_IF(failed(parser.parseOptionalKeyword(&strVal)),
           "expected valid level property (e.g. nonordered, nonunique or high)")
  if (strVal.compare("nonunique") == 0) {
    *properties |= static_cast<uint8_t>(LevelPropertyNondefault::Nonunique);
  } else if (strVal.compare("nonordered") == 0) {
    *properties |= static_cast<uint8_t>(LevelPropertyNondefault::Nonordered);
  } else {
    parser.emitError(loc, "unknown level property: ") << strVal;
    return failure();
  }
  return success();
}

//===----------------------------------------------------------------------===//
