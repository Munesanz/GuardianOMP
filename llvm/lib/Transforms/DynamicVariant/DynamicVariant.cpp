//===- StaticTDGIdent.cpp -- Strip parts of Debug Info --------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/DynamicVariant.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/ValueMapper.h"
using namespace llvm;

#define DEBUG_TYPE "dynamic-variant"

namespace {


struct DynamicVariant {
  DynamicVariant() {}

  bool runOnModule(Module &M) {
    if (M.empty())
      return false;

    bool VariantFound = false;
    for (auto &F : M) {
      // Nothing to do for declarations.
      if (F.isDeclaration() || F.empty())
        continue;

      // Vector to store pairs of dynamic variant calls and function vector
      SmallVector<std::pair<Instruction *, SmallVector<Function *, 8>>, 8>
          VariantCallsFound;

      // Vectors to traverse BB
      SmallVector<BasicBlock *, 8> Worklist;
      SmallPtrSet<BasicBlock *, 8> Visited;
      Worklist.push_back(&F.getEntryBlock());
      Visited.insert(&F.getEntryBlock());

      // Initialize IR Builder and dynamic variant runtime call
      IRBuilder<> IRB(&F.getEntryBlock());
      Type *returnType = IRB.getInt32Ty();
      std::vector<Type *> argTypes = {Type::getInt32PtrTy(M.getContext()),
                                      IRB.getInt32Ty(), Type::getInt32PtrTy(M.getContext()), IRB.getInt32Ty()};
      FunctionType *functionType =
          FunctionType::get(returnType, argTypes, false);
      auto DynVariantF =
          M.getOrInsertFunction("__kmpc_dynamic_variant", functionType);

      // Iterate over BB
      while (!Worklist.empty()) {
        auto WIt = Worklist.begin();
        BasicBlock *BB = *WIt;
        Worklist.erase(WIt);

        for (Instruction &I : *BB) {
          if (CallBase *FuncCall = dyn_cast<CallBase>(&I))
            if (FuncCall->getCalledFunction() &&
                !FuncCall->getCalledFunction()->isIntrinsic() &&
                FuncCall->getCalledFunction()->hasFnAttribute("variant")) {

              int ReplicaId = 0;
              llvm::MDNode *ReplicaIdNode =
                  FuncCall->getMetadata("task.replica.id");
              if (ReplicaIdNode)
                ReplicaId =
                    std::stoi(cast<MDString>(ReplicaIdNode->getOperand(0))
                                  ->getString()
                                  .str());

              VariantFound = true;
              // Get global structures names
              StringRef MainVariantName = FuncCall->getCalledFunction()
                                              ->getFnAttribute("variant")
                                              .getValueAsString();

              std::string VariantsName = MainVariantName.str() + "_variants";
              std::string TraitsName = MainVariantName.str() + "_traits";

              // Vector to store variants functions
              SmallVector<Function *, 8> VariantFuncions;

              // Obtain and store all variants functions
              GlobalVariable *FunctionsArray =
                  M.getGlobalVariable(VariantsName, true);
              ConstantArray *FunctionsConstantArray =
                  dyn_cast<ConstantArray>(FunctionsArray->getOperand(0));
              int numVariants = FunctionsConstantArray->getNumOperands();

              for (int i = 0; i < numVariants; i++) {
                VariantFuncions.push_back(
                    dyn_cast<Function>(FunctionsConstantArray->getOperand(i)));
              }

              // Build dynamic variant runtime call and store pair
              IRB.SetInsertPoint(&I);

              // Parse user conditions, look for annotations
              SmallVector<Value *, 2> UserConditions;
              Instruction *Start = I.getPrevNode();
              while (Start) {
                if (dyn_cast<CallBase>(Start) &&
                    !dyn_cast<IntrinsicInst>(Start))
                  break;
                else if (Start->getMetadata("annotation")) {
                  UserConditions.insert(UserConditions.begin(), Start);
                }
                Start = Start->getPrevNode();
              }

              Value *UserConditionsArray = ConstantPointerNull::get(
                  PointerType::getInt32PtrTy(M.getContext()));
              ArrayType *UserConditionsArrayType =
                  ArrayType::get(IRB.getInt32Ty(), UserConditions.size());
              // Store user conditions
              if (UserConditions.size()) {
                UserConditionsArray = IRB.CreateAlloca(UserConditionsArrayType);
                int Index = 0;
                for (Value *Condition : UserConditions) {
                   Value *GEP = IRB.CreateInBoundsGEP(
                       UserConditionsArrayType, UserConditionsArray,
                       {IRB.getInt32(0), IRB.getInt32(Index)});
                   if (dyn_cast<AllocaInst>(Condition))
                     Condition = IRB.CreateLoad(IRB.getInt1Ty(), Condition);
                   Value *ConditionBitcast =
                       IRB.CreateIntCast(Condition, IRB.getInt32Ty(), false);
                   IRB.CreateStore(ConditionBitcast, GEP);
                   Index++;
                }
              }

              GlobalVariable *TraitsArray =
                  M.getGlobalVariable(TraitsName, true);
              Value *TraitsBitCast = IRB.CreateBitCast(
                  TraitsArray, Type::getInt32PtrTy(M.getContext()));

              Value *UserConditionsArrayBitcast =
                  IRB.CreateInBoundsGEP(UserConditionsArrayType,
                                        UserConditionsArray, IRB.getInt32(0));

              Instruction *ChoosedVariant =
                  dyn_cast<Instruction>(IRB.CreateCall(
                      DynVariantF, {TraitsBitCast, IRB.getInt32(numVariants),
                                    UserConditionsArrayBitcast, IRB.getInt32(ReplicaId)}));

              VariantCallsFound.push_back(
                  std::make_pair(ChoosedVariant, VariantFuncions));
            }
        }

        for (auto It = succ_begin(BB); It != succ_end(BB); ++It) {
          if (!Visited.count(*It)) {
            Worklist.push_back(*It);
            Visited.insert(*It);
          }
        }
      }

      // The transformation alterates the BBs hierarchy, so we can only
      // transform after the BB iteration of the Function is done. All the
      // transformation needed are now stored in pairs inside VariantCallsFoung
      for (auto VariantPair : VariantCallsFound) {

        auto *I = VariantPair.first;
        auto Functions = VariantPair.second;

        // First, we create a switch just after the dynamic variant call
        auto *VariantCall = I->getNextNode();
        IRBuilder<> IRB(VariantCall);
        auto *VariantSwitch = IRB.CreateSwitch(I, I->getParent(), Functions.size());
        bool IsInvoke = false;
        BasicBlock *VariantEnd;

        if(InvokeInst *invk = dyn_cast<InvokeInst>(VariantCall)) {
          VariantEnd = invk->getNormalDest();
          IsInvoke = true;
        }
        else{
        // Second, we split the BB after the switch. This is the variant_end
          VariantEnd =
            (I->getParent())
                ->splitBasicBlock(VariantSwitch->getNextNode(), "variant_end");
        }

        // Then, for each variant we create a separate BB
        for (int i = 0; i < (int)Functions.size(); i++) {
          BasicBlock *SwitchCase =
              BasicBlock::Create(M.getContext(), "variant", &F, VariantEnd);
          IRB.SetInsertPoint(SwitchCase);

          auto *NewVariantCall = VariantCall->clone();
          CallBase *Cast = dyn_cast<CallBase>(NewVariantCall);
          Cast->setCalledFunction(Functions[i]);

          if (IsInvoke) {
            IRB.Insert(NewVariantCall);
          } else {
            // Create terminator
            auto *CaseTerminator = IRB.CreateBr(VariantEnd);
            // Clone the variant call and replace the called function. This
            // works as all variants must maintain the same call arguments
            NewVariantCall->insertBefore(CaseTerminator);
          }
          // Add new case to the switch
          VariantSwitch->addCase(IRB.getInt32(i), SwitchCase);
        }

        // Add the default switch case, that corresponds to the original
        // compiler variant.
        BasicBlock *DefaultCase = BasicBlock::Create(
            M.getContext(), "default_variant", &F, VariantEnd);
        IRB.SetInsertPoint(DefaultCase);
        auto *NewVariantCall = VariantCall->clone();
        if (IsInvoke) {
          IRB.Insert(NewVariantCall);
        } else {
          auto *CaseTerminator = IRB.CreateBr(VariantEnd);
          NewVariantCall->insertBefore(CaseTerminator);
        }

        // Replace switch default dest, remove unnecesary BB terminator added by
        // the split, and remove the original compiler variant call
        VariantSwitch->setDefaultDest(DefaultCase);
        if (!IsInvoke)
          VariantSwitch->getNextNode()->eraseFromParent();
        VariantCall->eraseFromParent();
      }
    }

    // Remove all function variant attributes. This will prevent the compiler
    // from generating the variants twice in case this optimizacion runs again
    for (auto &F : M)
      F.removeFnAttr("variant");

    return VariantFound;
  }
};

struct DynamicVariantLegacyPass : public ModulePass {
  /// Pass identification, replacement for typeid
  static char ID;
  DynamicVariantLegacyPass() : ModulePass(ID) {
    initializeDynamicVariantLegacyPassPass(*PassRegistry::getPassRegistry());
  }

  bool runOnModule(Module &M) override {
    if (skipModule(M))
      return false;

    // See below for the reason of this.
    return DynamicVariant().runOnModule(M);
  }

  StringRef getPassName() const override {
    return "Replace variants with a dynamic runtime decision";
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
  }
};

} // namespace

char DynamicVariantLegacyPass::ID = 0;

ModulePass *llvm::createDynamicVariantLegacyPass() {
  return new DynamicVariantLegacyPass();
}

void LLVMDynamicVariantPass(LLVMPassManagerRef PM) {
  unwrap(PM)->add(createDynamicVariantLegacyPass());
}

INITIALIZE_PASS_BEGIN(DynamicVariantLegacyPass, "dynamic-variant",
                      "Replace variants with a dynamic runtime decision", false, false)
INITIALIZE_PASS_END(DynamicVariantLegacyPass, "dynamic-variant",
                    "Replace variants with a dynamic runtime decision", false, false)

// New pass manager.
PreservedAnalyses DynamicVariantPass::run(Module &M,
                                          ModuleAnalysisManager &AM) {
  // This is an adapter that will be used to get the analysis data of a given
  // function. This is done this way so we can reuse the code for the new and
  // legacy pass manager (they used different functions to get this
  // information).
  if (!DynamicVariant().runOnModule(M))
    return PreservedAnalyses::all();

  // FIXME: we can be more precise here.
  return PreservedAnalyses::none();
}
