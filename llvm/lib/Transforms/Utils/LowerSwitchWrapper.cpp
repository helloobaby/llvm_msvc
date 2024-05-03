//===- LowerSwitchWrapper.cpp - Eliminate Switch instructions
//--------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// The LowerSwitchWrapper transformation rewrites switch instructions with a
// sequence of branches, which allows targets to get away with not implementing
// the switch instruction until it is convenient.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Utils/LowerSwitchWrapper.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Value.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <limits>
#include <vector>

using namespace llvm;

#define DEBUG_TYPE "lower-switch-wrapper"

namespace {

struct IntRange {
  APInt Low, High;
};

} // end anonymous namespace

// Return true iff R is covered by Ranges.
static bool IsInRanges(const IntRange &R, const std::vector<IntRange> &Ranges) {
  // Note: Ranges must be sorted, non-overlapping and non-adjacent.

  // Find the first range whose High field is >= R.High,
  // then check if the Low field is <= R.Low. If so, we
  // have a Range that covers R.
  auto I = llvm::lower_bound(
      Ranges, R, [](IntRange A, IntRange B) { return A.High.slt(B.High); });
  return I != Ranges.end() && I->Low.sle(R.Low);
}

namespace {

/// Replace all SwitchInst instructions with chained branch instructions.
class LowerSwitchWrapper : public FunctionPass {
public:
  // Pass identification, replacement for typeid
  static char ID;

  LowerSwitchWrapper() : FunctionPass(ID) {}

  bool runOnFunction(Function &F) override;

  struct CaseRange {
    ConstantInt *Low;
    ConstantInt *High;
    BasicBlock *BB;

    CaseRange(ConstantInt *low, ConstantInt *high, BasicBlock *bb)
        : Low(low), High(high), BB(bb) {}
  };

  using CaseVector = std::vector<CaseRange>;
  using CaseItr = std::vector<CaseRange>::iterator;

private:
  void processSwitchInst(SwitchInst *SI,
                         SmallPtrSetImpl<BasicBlock *> &DeleteList);

  BasicBlock *switchConvert(CaseItr Begin, CaseItr End, ConstantInt *LowerBound,
                            ConstantInt *UpperBound, Value *Val,
                            BasicBlock *Predecessor, BasicBlock *OrigBlock,
                            BasicBlock *Default,
                            const std::vector<IntRange> &UnreachableRanges);
  BasicBlock *newLeafBlock(CaseRange &Leaf, Value *Val, ConstantInt *LowerBound,
                           ConstantInt *UpperBound, BasicBlock *OrigBlock,
                           BasicBlock *Default);
  unsigned clusterify(CaseVector &Cases, SwitchInst *SI);
};

/// The comparison function for sorting the switch case values in the vector.
/// WARNING: Case ranges should be disjoint!
struct CaseCmp {
  bool operator()(const LowerSwitchWrapper::CaseRange &C1,
                  const LowerSwitchWrapper::CaseRange &C2) {
    const ConstantInt *CI1 = cast<const ConstantInt>(C1.Low);
    const ConstantInt *CI2 = cast<const ConstantInt>(C2.High);
    return CI1->getValue().slt(CI2->getValue());
  }
};

} // end anonymous namespace

char LowerSwitchWrapper::ID = 0;

// createLowerSwitchWrapperPass - Interface to this file...
FunctionPass *llvm::createLowerSwitchWrapperPass() {
  return new LowerSwitchWrapper();
}

bool LowerSwitchWrapper::runOnFunction(Function &F) {
  bool Changed = false;
  SmallPtrSet<BasicBlock *, 8> DeleteList;

  for (BasicBlock &Cur : llvm::make_early_inc_range(F)) {
    // If the block is a dead Default block that will be deleted later, don't
    // waste time processing it.
    if (DeleteList.count(&Cur))
      continue;

    if (SwitchInst *SI = dyn_cast<SwitchInst>(Cur.getTerminator())) {
      Changed = true;
      processSwitchInst(SI, DeleteList);
    }
  }

  for (BasicBlock *BB : DeleteList) {
    DeleteDeadBlock(BB);
  }

  return Changed;
}

/// Used for debugging purposes.
LLVM_ATTRIBUTE_USED
static raw_ostream &operator<<(raw_ostream &O,
                               const LowerSwitchWrapper::CaseVector &C) {
  O << "[";

  for (LowerSwitchWrapper::CaseVector::const_iterator B = C.begin(),
                                                      E = C.end();
       B != E;) {
    O << *B->Low << " -" << *B->High;
    if (++B != E)
      O << ", ";
  }

  return O << "]";
}

/// Update the first occurrence of the "switch statement" BB in the PHI
/// node with the "new" BB. The other occurrences will:
///
/// 1) Be updated by subsequent calls to this function.  Switch statements may
/// have more than one outcoming edge into the same BB if they all have the same
/// value. When the switch statement is converted these incoming edges are now
/// coming from multiple BBs.
/// 2) Removed if subsequent incoming values now share the same case, i.e.,
/// multiple outcome edges are condensed into one. This is necessary to keep the
/// number of phi values equal to the number of branches to SuccBB.
static void fixPhis(BasicBlock *SuccBB, BasicBlock *OrigBB, BasicBlock *NewBB,
                    const APInt &NumMergedCases) {
  for (auto &I : SuccBB->phis()) {
    PHINode *PN = cast<PHINode>(&I);

    // Only update the first occurrence if NewBB exists.
    unsigned Idx = 0, E = PN->getNumIncomingValues();
    APInt LocalNumMergedCases = NumMergedCases;
    for (; Idx != E && NewBB; ++Idx) {
      if (PN->getIncomingBlock(Idx) == OrigBB) {
        PN->setIncomingBlock(Idx, NewBB);
        break;
      }
    }

    // Skip the updated incoming block so that it will not be removed.
    if (NewBB)
      ++Idx;

    // Remove additional occurrences coming from condensed cases and keep the
    // number of incoming values equal to the number of branches to SuccBB.
    SmallVector<unsigned, 8> Indices;
    for (; LocalNumMergedCases.ugt(0) && Idx < E; ++Idx)
      if (PN->getIncomingBlock(Idx) == OrigBB) {
        Indices.push_back(Idx);
        LocalNumMergedCases -= 1;
      }
    // Remove incoming values in the reverse order to prevent invalidating
    // *successive* index.
    for (unsigned III : llvm::reverse(Indices))
      PN->removeIncomingValue(III);
  }
}

/// Convert the switch statement into a binary lookup of the case values.
/// The function recursively builds this tree. LowerBound and UpperBound are
/// used to keep track of the bounds for Val that have already been checked by
/// a block emitted by one of the previous calls to switchConvert in the call
/// stack.
BasicBlock *LowerSwitchWrapper::switchConvert(
    CaseItr Begin, CaseItr End, ConstantInt *LowerBound,
    ConstantInt *UpperBound, Value *Val, BasicBlock *Predecessor,
    BasicBlock *OrigBlock, BasicBlock *Default,
    const std::vector<IntRange> &UnreachableRanges) {
  assert(LowerBound && UpperBound && "Bounds must be initialized");
  unsigned Size = End - Begin;

  if (Size == 1) {
    // Check if the Case Range is perfectly squeezed in between
    // already checked Upper and Lower bounds. If it is then we can avoid
    // emitting the code that checks if the value actually falls in the range
    // because the bounds already tell us so.
    if (Begin->Low == LowerBound && Begin->High == UpperBound) {
      APInt NumMergedCases = UpperBound->getValue() - LowerBound->getValue();
      fixPhis(Begin->BB, OrigBlock, Predecessor, NumMergedCases);
      return Begin->BB;
    }
    return newLeafBlock(*Begin, Val, LowerBound, UpperBound, OrigBlock,
                        Default);
  }

  unsigned Mid = Size / 2;
  std::vector<CaseRange> LHS(Begin, Begin + Mid);
  LLVM_DEBUG(dbgs() << "LHS: " << LHS << "\n");
  std::vector<CaseRange> RHS(Begin + Mid, End);
  LLVM_DEBUG(dbgs() << "RHS: " << RHS << "\n");

  CaseRange &Pivot = *(Begin + Mid);
  LLVM_DEBUG(dbgs() << "Pivot ==> " << Pivot.Low->getValue() << " -"
                    << Pivot.High->getValue() << "\n");

  // NewLowerBound here should never be the integer minimal value.
  // This is because it is computed from a case range that is never
  // the smallest, so there is always a case range that has at least
  // a smaller value.
  ConstantInt *NewLowerBound = Pivot.Low;

  // Because NewLowerBound is never the smallest representable integer
  // it is safe here to subtract one.
  ConstantInt *NewUpperBound = ConstantInt::get(NewLowerBound->getContext(),
                                                NewLowerBound->getValue() - 1);

  if (!UnreachableRanges.empty()) {
    // Check if the gap between LHS's highest and NewLowerBound is unreachable.
    APInt GapLow = LHS.back().High->getValue() + 1;
    APInt GapHigh = NewLowerBound->getValue() - 1;
    IntRange Gap = {GapLow, GapHigh};
    if (GapHigh.sge(GapLow) && IsInRanges(Gap, UnreachableRanges))
      NewUpperBound = LHS.back().High;
  }

  LLVM_DEBUG(
      dbgs() << "LHS Bounds ==> "; if (LowerBound) {
        dbgs() << LowerBound->getSExtValue();
      } else {
        dbgs() << "NONE";
      } dbgs() << " - "
               << NewUpperBound->getSExtValue() << "\n";
      dbgs() << "RHS Bounds ==> ";
      dbgs() << NewLowerBound->getSExtValue() << " - "; if (UpperBound) {
        dbgs() << UpperBound->getSExtValue() << "\n";
      } else { dbgs() << "NONE\n"; });

  // Create a new node that checks if the value is < pivot. Go to the
  // left branch if it is and right branch if not.
  Function *F = OrigBlock->getParent();
  BasicBlock *NewNode = BasicBlock::Create(Val->getContext(), "NodeBlock");

  ICmpInst *Comp = new ICmpInst(ICmpInst::ICMP_SLT, Val, Pivot.Low, "Pivot");

  BasicBlock *LBranch =
      switchConvert(LHS.begin(), LHS.end(), LowerBound, NewUpperBound, Val,
                    NewNode, OrigBlock, Default, UnreachableRanges);
  BasicBlock *RBranch =
      switchConvert(RHS.begin(), RHS.end(), NewLowerBound, UpperBound, Val,
                    NewNode, OrigBlock, Default, UnreachableRanges);

  F->insert(++OrigBlock->getIterator(), NewNode);
  Comp->insertInto(NewNode, NewNode->end());

  BranchInst::Create(LBranch, RBranch, Comp, NewNode);
  return NewNode;
}

/// Create a new leaf block for the binary lookup tree. It checks if the
/// switch's value == the case's value. If not, then it jumps to the default
/// branch. At this point in the tree, the value can't be another valid case
/// value, so the jump to the "default" branch is warranted.
BasicBlock *LowerSwitchWrapper::newLeafBlock(CaseRange &Leaf, Value *Val,
                                             ConstantInt *LowerBound,
                                             ConstantInt *UpperBound,
                                             BasicBlock *OrigBlock,
                                             BasicBlock *Default) {
  Function *F = OrigBlock->getParent();
  BasicBlock *NewLeaf = BasicBlock::Create(Val->getContext(), "LeafBlock");
  F->getBasicBlockList().insert(++OrigBlock->getIterator(), NewLeaf);

  // Emit comparison
  ICmpInst *Comp = nullptr;
  if (Leaf.Low == Leaf.High) {
    // Make the seteq instruction...
    Comp =
        new ICmpInst(*NewLeaf, ICmpInst::ICMP_EQ, Val, Leaf.Low, "SwitchLeaf");
  } else {
    // Make range comparison
    if (Leaf.Low == LowerBound) {
      // Val >= Min && Val <= Hi --> Val <= Hi
      Comp = new ICmpInst(*NewLeaf, ICmpInst::ICMP_SLE, Val, Leaf.High,
                          "SwitchLeaf");
    } else if (Leaf.High == UpperBound) {
      // Val <= Max && Val >= Lo --> Val >= Lo
      Comp = new ICmpInst(*NewLeaf, ICmpInst::ICMP_SGE, Val, Leaf.Low,
                          "SwitchLeaf");
    } else if (Leaf.Low->isZero()) {
      // Val >= 0 && Val <= Hi --> Val <=u Hi
      Comp = new ICmpInst(*NewLeaf, ICmpInst::ICMP_ULE, Val, Leaf.High,
                          "SwitchLeaf");
    } else {
      // Emit V-Lo <=u Hi-Lo
      Constant *NegLo = ConstantExpr::getNeg(Leaf.Low);
      Instruction *Add = BinaryOperator::CreateAdd(
          Val, NegLo, Val->getName() + ".off", NewLeaf);
      Constant *UpperBound = ConstantExpr::getAdd(NegLo, Leaf.High);
      Comp = new ICmpInst(*NewLeaf, ICmpInst::ICMP_ULE, Add, UpperBound,
                          "SwitchLeaf");
    }
  }

  // Make the conditional branch...
  BasicBlock *Succ = Leaf.BB;
  BranchInst::Create(Succ, Default, Comp, NewLeaf);

  // Update the PHI incoming value/block for the default.
  for (auto &I : Default->phis()) {
    PHINode *PN = cast<PHINode>(&I);
    auto *V = PN->getIncomingValueForBlock(OrigBlock);
    PN->addIncoming(V, NewLeaf);
  }

  // If there were any PHI nodes in this successor, rewrite one entry
  // from OrigBlock to come from NewLeaf.
  for (BasicBlock::iterator I = Succ->begin(); isa<PHINode>(I); ++I) {
    PHINode *PN = cast<PHINode>(I);
    // Remove all but one incoming entries from the cluster
    APInt Range = Leaf.High->getValue() - Leaf.Low->getValue();
    for (APInt j(Range.getBitWidth(), 0, true); j.slt(Range); ++j) {
      PN->removeIncomingValue(OrigBlock);
    }

    int BlockIdx = PN->getBasicBlockIndex(OrigBlock);
    assert(BlockIdx != -1 && "Switch didn't go to this successor??");
    PN->setIncomingBlock((unsigned)BlockIdx, NewLeaf);
  }

  return NewLeaf;
}

/// Transform simple list of Cases into list of CaseRange's.
unsigned LowerSwitchWrapper::clusterify(CaseVector &Cases, SwitchInst *SI) {
  unsigned NumSimpleCases = 0;

  // Start with "simple" cases
  for (auto Case : SI->cases()) {
    if (Case.getCaseSuccessor() == SI->getDefaultDest())
      continue;
    Cases.push_back(CaseRange(Case.getCaseValue(), Case.getCaseValue(),
                              Case.getCaseSuccessor()));
    ++NumSimpleCases;
  }

  llvm::sort(Cases, CaseCmp());

  // Merge case into clusters
  if (Cases.size() >= 2) {
    CaseItr I = Cases.begin();
    for (CaseItr J = std::next(I), E = Cases.end(); J != E; ++J) {
      const APInt &nextValue = J->Low->getValue();
      const APInt &currentValue = I->High->getValue();
      BasicBlock *nextBB = J->BB;
      BasicBlock *currentBB = I->BB;

      // If the two neighboring cases go to the same destination, merge them
      // into a single case.
      assert(nextValue.sgt(currentValue) &&
             "Cases should be strictly ascending");
      if ((nextValue == currentValue + 1) && (currentBB == nextBB)) {
        I->High = J->High;
        // FIXME: Combine branch weights.
      } else if (++I != J) {
        *I = *J;
      }
    }
    Cases.erase(std::next(I), Cases.end());
  }

  return NumSimpleCases;
}

/// Replace the specified switch instruction with a sequence of chained if-then
/// insts in a balanced binary search.
void LowerSwitchWrapper::processSwitchInst(
    SwitchInst *SI, SmallPtrSetImpl<BasicBlock *> &DeleteList) {
  BasicBlock *OrigBlock = SI->getParent();
  Function *F = OrigBlock->getParent();
  Value *Val = SI->getCondition(); // The value we are switching on...
  BasicBlock *Default = SI->getDefaultDest();

  // Don't handle unreachable blocks. If there are successors with phis, this
  // would leave them behind with missing predecessors.
  if ((OrigBlock != &F->getEntryBlock() && pred_empty(OrigBlock)) ||
      OrigBlock->getSinglePredecessor() == OrigBlock) {
    DeleteList.insert(OrigBlock);
    return;
  }

  // Prepare cases vector.
  CaseVector Cases;
  const unsigned NumSimpleCases = clusterify(Cases, SI);
  IntegerType *IT = cast<IntegerType>(SI->getCondition()->getType());
  const unsigned BitWidth = IT->getBitWidth();
  // Explictly use higher precision to prevent unsigned overflow where
  // `UnsignedMax - 0 + 1 == 0`
  APInt UnsignedZero(BitWidth + 1, 0);
  APInt UnsignedMax = APInt::getMaxValue(BitWidth);
  LLVM_DEBUG(dbgs() << "Clusterify finished. Total clusters: " << Cases.size()
                    << ". Total non-default cases: " << NumSimpleCases
                    << "\nCase clusters: " << Cases << "\n");

  // If there is only the default destination, just branch.
  if (Cases.empty()) {
    BranchInst::Create(Default, OrigBlock);
    // Remove all the references from Default's PHIs to OrigBlock, but one.
    fixPhis(Default, OrigBlock, OrigBlock, UnsignedMax);
    SI->eraseFromParent();
    return;
  }

  ConstantInt *LowerBound = nullptr;
  ConstantInt *UpperBound = nullptr;
  std::vector<IntRange> UnreachableRanges;

  if (isa<UnreachableInst>(Default->getFirstNonPHIOrDbg())) {
    // Make the bounds tightly fitted around the case value range, because we
    // know that the value passed to the switch must be exactly one of the case
    // values.
    assert(!Cases.empty());
    LowerBound = Cases.front().Low;
    UpperBound = Cases.back().High;

    DenseMap<BasicBlock *, APInt> Popularity;
    APInt MaxPop(UnsignedZero);
    BasicBlock *PopSucc = nullptr;

    APInt SignedMax = APInt::getSignedMaxValue(BitWidth);
    APInt SignedMin = APInt::getSignedMinValue(BitWidth);
    IntRange R = {SignedMin, SignedMax};
    UnreachableRanges.push_back(R);
    for (const auto &I : Cases) {
      const APInt &Low = I.Low->getValue();
      const APInt &High = I.High->getValue();

      IntRange &LastRange = UnreachableRanges.back();
      if (LastRange.Low == Low) {
        // There is nothing left of the previous range.
        UnreachableRanges.pop_back();
      } else {
        // Terminate the previous range.
        LastRange.High = Low - 1;
      }
      if (High != std::numeric_limits<int64_t>::max()) {
        IntRange R = {High + 1, SignedMax};
        UnreachableRanges.push_back(R);
      }

      // Count popularity.
      assert(High.sge(Low) && "Popularity shouldn't be negative.");
      APInt N = High.sext(BitWidth + 1) - Low.sext(BitWidth + 1) + 1;
      // Explict insert to make sure the bitwidth of APInts match
      APInt &Pop = Popularity.insert({I.BB, APInt(UnsignedZero)}).first->second;
      if ((Pop += N).ugt(MaxPop)) {
        MaxPop = Pop;
        PopSucc = I.BB;
      }
    }

    // As the default block in the switch is unreachable, update the PHI nodes
    // (remove all of the references to the default block) to reflect this.
    const unsigned NumDefaultEdges = SI->getNumCases() + 1 - NumSimpleCases;
    for (unsigned I = 0; I < NumDefaultEdges; ++I)
      Default->removePredecessor(OrigBlock);

    // Use the most popular block as the new default, reducing the number of
    // cases.
    Default = PopSucc;
    llvm::erase_if(Cases,
                   [PopSucc](const CaseRange &R) { return R.BB == PopSucc; });

    // If there are no cases left, just branch.
    if (Cases.empty()) {
      BranchInst::Create(Default, OrigBlock);
      SI->eraseFromParent();
      // As all the cases have been replaced with a single branch, only keep
      // one entry in the PHI nodes.
      if (!MaxPop.isZero())
        for (APInt I(UnsignedZero); I.ult(MaxPop - 1); ++I)
          PopSucc->removePredecessor(OrigBlock);
      return;
    }

    // If the condition was a PHI node with the switch block as a predecessor
    // removing predecessors may have caused the condition to be erased.
    // Getting the condition value again here protects against that.
    Val = SI->getCondition();
  }

  BasicBlock *SwitchBlock =
      switchConvert(Cases.begin(), Cases.end(), LowerBound, UpperBound, Val,
                    OrigBlock, OrigBlock, Default, UnreachableRanges);

  // We have added incoming values for newly-created predecessors in
  // NewLeafBlock(). The only meaningful work we offload to FixPhis() is to
  // remove the incoming values from OrigBlock. There might be a special case
  // that SwitchBlock is the same as Default, under which the PHIs in Default
  // are fixed inside SwitchConvert().
  if (SwitchBlock != Default)
    fixPhis(Default, OrigBlock, nullptr, UnsignedMax);

  // Branch to our shiny new if-then stuff...
  BranchInst::Create(SwitchBlock, OrigBlock);

  // We are now done with the switch instruction, delete it.
  BasicBlock *OldDefault = SI->getDefaultDest();
  SI->eraseFromParent();

  // If the Default block has no more predecessors just add it to DeleteList.
  if (pred_empty(OldDefault))
    DeleteList.insert(OldDefault);
}
