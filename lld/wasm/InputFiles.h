//===- InputFiles.h ---------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLD_WASM_INPUT_FILES_H
#define LLD_WASM_INPUT_FILES_H

#include "Symbols.h"
#include "lld/Common/LLVM.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/LTO/LTO.h"
#include "llvm/Object/Archive.h"
#include "llvm/Object/Wasm.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/TargetParser/Triple.h"
#include <optional>
#include <vector>

namespace llvm {
class TarWriter;
}

namespace lld {
namespace wasm {

class InputChunk;
class InputFunction;
class InputSegment;
class InputGlobal;
class InputTag;
class InputTable;
class InputSection;

// If --reproduce option is given, all input files are written
// to this tar archive.
extern std::unique_ptr<llvm::TarWriter> tar;

class InputFile {
public:
  enum Kind {
    ObjectKind,
    SharedKind,
    ArchiveKind,
    BitcodeKind,
    StubKind,
  };

  virtual ~InputFile() {}

  // Returns the filename.
  StringRef getName() const { return mb.getBufferIdentifier(); }

  Kind kind() const { return fileKind; }

  // An archive file name if this file is created from an archive.
  std::string archiveName;

  ArrayRef<Symbol *> getSymbols() const { return symbols; }

  MutableArrayRef<Symbol *> getMutableSymbols() { return symbols; }

  // An InputFile is considered live if any of the symbols defined by it
  // are live.
  void markLive() { live = true; }
  bool isLive() const { return live; }

protected:
  InputFile(Kind k, MemoryBufferRef m)
      : mb(m), fileKind(k), live(!config->gcSections) {}

  void checkArch(llvm::Triple::ArchType arch) const;

  MemoryBufferRef mb;

  // List of all symbols referenced or defined by this file.
  std::vector<Symbol *> symbols;

private:
  const Kind fileKind;
  bool live;
};

// .a file (ar archive)
class ArchiveFile : public InputFile {
public:
  explicit ArchiveFile(MemoryBufferRef m) : InputFile(ArchiveKind, m) {}
  static bool classof(const InputFile *f) { return f->kind() == ArchiveKind; }

  void addMember(const llvm::object::Archive::Symbol *sym);

  void parse();

private:
  std::unique_ptr<llvm::object::Archive> file;
  llvm::DenseSet<uint64_t> seen;
};

// .o file (wasm object file)
class ObjFile : public InputFile {
public:
  explicit ObjFile(MemoryBufferRef m, StringRef archiveName)
      : InputFile(ObjectKind, m) {
    this->archiveName = std::string(archiveName);

    // If this isn't part of an archive, it's eagerly linked, so mark it live.
    if (archiveName.empty())
      markLive();
  }
  static bool classof(const InputFile *f) { return f->kind() == ObjectKind; }

  void parse(bool ignoreComdats = false);

  // Returns the underlying wasm file.
  const WasmObjectFile *getWasmObj() const { return wasmObj.get(); }

  uint32_t calcNewIndex(const WasmRelocation &reloc) const;
  uint64_t calcNewValue(const WasmRelocation &reloc, uint64_t tombstone,
                        const InputChunk *chunk) const;
  int64_t calcNewAddend(const WasmRelocation &reloc) const;
  Symbol *getSymbol(const WasmRelocation &reloc) const {
    return symbols[reloc.Index];
  };

  const WasmSection *codeSection = nullptr;
  const WasmSection *dataSection = nullptr;

  // Maps input type indices to output type indices
  std::vector<uint32_t> typeMap;
  std::vector<bool> typeIsUsed;
  // Maps function indices to table indices
  std::vector<uint32_t> tableEntries;
  std::vector<uint32_t> tableEntriesRel;
  std::vector<bool> keptComdats;
  std::vector<InputChunk *> segments;
  std::vector<InputFunction *> functions;
  std::vector<InputGlobal *> globals;
  std::vector<InputTag *> tags;
  std::vector<InputTable *> tables;
  std::vector<InputChunk *> customSections;
  llvm::DenseMap<uint32_t, InputChunk *> customSectionsByIndex;

  Symbol *getSymbol(uint32_t index) const { return symbols[index]; }
  FunctionSymbol *getFunctionSymbol(uint32_t index) const;
  DataSymbol *getDataSymbol(uint32_t index) const;
  GlobalSymbol *getGlobalSymbol(uint32_t index) const;
  SectionSymbol *getSectionSymbol(uint32_t index) const;
  TagSymbol *getTagSymbol(uint32_t index) const;
  TableSymbol *getTableSymbol(uint32_t index) const;

private:
  Symbol *createDefined(const WasmSymbol &sym);
  Symbol *createUndefined(const WasmSymbol &sym, bool isCalledDirectly);

  bool isExcludedByComdat(const InputChunk *chunk) const;
  void addLegacyIndirectFunctionTableIfNeeded(uint32_t tableSymbolCount);

  std::unique_ptr<WasmObjectFile> wasmObj;
};

// .so file.
class SharedFile : public InputFile {
public:
  explicit SharedFile(MemoryBufferRef m) : InputFile(SharedKind, m) {}
  static bool classof(const InputFile *f) { return f->kind() == SharedKind; }
};

// .bc file
class BitcodeFile : public InputFile {
public:
  BitcodeFile(MemoryBufferRef m, StringRef archiveName,
              uint64_t offsetInArchive);
  static bool classof(const InputFile *f) { return f->kind() == BitcodeKind; }

  void parse(StringRef symName);
  std::unique_ptr<llvm::lto::InputFile> obj;

  // Set to true once LTO is complete in order prevent further bitcode objects
  // being added.
  static bool doneLTO;
};

// Stub library (See docs/WebAssembly.rst)
class StubFile : public InputFile {
public:
  explicit StubFile(MemoryBufferRef m) : InputFile(StubKind, m) {}

  static bool classof(const InputFile *f) { return f->kind() == StubKind; }

  void parse();

  llvm::DenseMap<StringRef, std::vector<StringRef>> symbolDependencies;
};

inline bool isBitcode(MemoryBufferRef mb) {
  return identify_magic(mb.getBuffer()) == llvm::file_magic::bitcode;
}

// Will report a fatal() error if the input buffer is not a valid bitcode
// or wasm object file.
InputFile *createObjectFile(MemoryBufferRef mb, StringRef archiveName = "",
                            uint64_t offsetInArchive = 0);

// Opens a given file.
std::optional<MemoryBufferRef> readFile(StringRef path);

} // namespace wasm

std::string toString(const wasm::InputFile *file);

} // namespace lld

#endif
