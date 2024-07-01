import os
import argparse
from myParser import CParser
from myRepeater import myRepeater


class Comparator:
    def __init__(self, baseDict: dict, curDict : dict, limit: int = 5):
        self.outputLimit = limit
        self.res = 0
        self.compFull = 0
        self.compMiss = 0
        self.compExtr = 0
        self.topMiss = {}
        self.topExtr = {}
        self.noSpec = []
        self.noVar = []
        self.functions = {}
        self.baseDict = baseDict
        self.curDict = curDict
        self.funcAmount = len(baseDict)

    def varMapping(self, baseFunc: dict, curFunc: dict) -> dict: # Get variables' values mappings
        intersection, baseDiff, curDiff = intersectDicts(baseFunc['param_types'], curFunc['param_types'])
        # print(f"I: {intersection}; bD: {baseDiff}; cD: {curDiff}")

        mapping = {k: k for k in intersection}

        for baseKey, baseVal in baseDiff.items():
            for curKey, curVal in curDiff.items():
                if cmpTypes(baseVal, curVal):
                    mapping[baseKey] = curKey
                    del curDiff[curKey]
                    break
            if baseKey not in mapping:
                mapping[baseKey] = 'None'
        
        mapping['None'] = []
        for curKey, _ in curDiff.items():
            mapping['None'] += [curKey]

        if '' in baseFunc:
            if '' in curFunc:
                mapping[''] = ''
            else:
                mapping[''] = 'None'
        return mapping

    def incRes(self, funcRes: tuple):
        funcName, compRes, compFull, compMiss, compExtr, func = funcRes

        self.res = min(self.res + compRes, self.funcAmount)
        self.compFull += compFull
        self.compMiss += compMiss
        self.compExtr += compExtr
        self.functions[funcName] = func
        # handle cur functions misses

    def cmpFunctions(self, funcName: str, baseFunc, curFunc) -> tuple:
        # print(funcName)
        # Get variables' values mappings
        mapping = self.varMapping(baseFunc, curFunc)

        # Get variables amount
        var_amount = len(mapping) + len(mapping.setdefault('None', [])) - 1

        # Init values
        var_res = 0
        var_compare_full = True
        var_compare_miss = 0
        var_compare_extr = 0
        funcValues = {"miss": [], "extr": [], "hit": [], "val": .0}

        # Functions with 0 variables handle
        if var_amount == 0:
            # print(f"{funcName} <-- has zero variables\n {baseFunc}")
            self.res += 1
            self.noVar += [funcName]
            return funcName, 1.0, True, 0, 0, funcValues

        for var, dvar in mapping.items():
            if var == 'param_types':
                continue

            if dvar == 'None':
                for func in baseFunc[var]:
                    self.topMiss[func] = self.topMiss.setdefault(func, 0) + 1
                    funcValues["miss"] += [func]
                var_compare_miss += 1
                continue

            if var == 'None':
                for x in dvar:
                    for func in curFunc[x]:
                        self.topExtr[func] = self.topExtr.setdefault(func, 0) + 1
                        funcValues["extr"] += [func]
                    var_compare_extr += 1
                continue

            # Get dicts for the current variable to compare
            baseVarFunctions, curVarFunctions = baseFunc[var], curFunc[dvar]

            # print(f"{var} - {dvar}; In: {len(list(set(curVarFunctions) & set(baseVarFunctions)))}\
            #     D1: {list(set(baseVarFunctions).difference(curVarFunctions))};\
            #     D2: {list(set(curVarFunctions).difference(baseVarFunctions))};\n")
            
            miss_fl, extr_fl = False, False
            # Get info about the missed functions
            for missFunction in list(set(baseVarFunctions).difference(curVarFunctions)):
                self.topMiss[missFunction] = self.topMiss.setdefault(missFunction, 0) + 1
                funcValues["miss"] += [missFunction]
                miss_fl = True

            # Get info about the extra functions
            for extrFunction in list(set(curVarFunctions).difference(baseVarFunctions)):
                self.topExtr[extrFunction] = self.topExtr.setdefault(extrFunction, 0) + 1
                funcValues["extr"] += [extrFunction]
                extr_fl = True

            # Increase according to intersection of the functions
            var_res += len(list(set(curVarFunctions) & set(baseVarFunctions))) / len(baseVarFunctions) if baseVarFunctions else 1.0

            if miss_fl:
                var_compare_miss += 1
                var_compare_full = False
            if extr_fl:
                var_compare_extr += 1
                var_compare_full = False
        
        funcValues["val"] = len(funcValues["miss"]) + len(funcValues["extr"]) + var_res
        
        # print(funcName,\
        #     var_res / var_amount,\
        #     var_compare_full,\
        #     var_compare_miss / var_amount,\
        #     var_compare_extr / var_amount,\
        #     funcValues)
        
        return funcName,\
            var_res / var_amount,\
            var_compare_full,\
            var_compare_miss / var_amount,\
            var_compare_extr / var_amount,\
            funcValues

    def getResult(self):
        for funcName in self.baseDict:
            # print(funcName)
            
            # Generation error functions counter
            if funcName not in self.curDict:
                self.noSpec += [funcName]
                continue

            # Get dicts for the current function to compare
            baseFunc, curFunc = self.baseDict[funcName], self.curDict[funcName]

            # Increase Result values according to the checked function
            self.incRes(self.cmpFunctions(funcName, baseFunc, curFunc))

        return 100 * self.res / self.funcAmount,\
            100 * self.compFull / self.funcAmount,\
            100 * self.compMiss / self.funcAmount,\
            100 * self.compExtr / self.funcAmount,\
            100 * len(self.noSpec) / self.funcAmount,\
            pairSort(self.topExtr, self.outputLimit),\
            pairSort(self.topMiss, self.outputLimit),\
            self.noSpec[:self.outputLimit],\
            dictSort(self.functions, self.outputLimit)
            # dict(filter(lambda x: x[1]["val"] < 0.5 , sorted(self.functions.items(), key=lambda x: x[1]["val"])))


def pairSort(var: dict, amount: int = None) -> dict:
    amount = len(var) if amount is None else amount
    return dict(sorted(var.items(), key=lambda x: x[1], reverse=True)[:amount])


def dictSort(var: dict, amount: int = None, reverseFl: bool = True) -> dict:
    amount = len(var) if amount is None else amount
    return dict(sorted(var.items(), key=lambda x: x[1]['val'], reverse=reverseFl)[:amount])


def cmpTypes(typeDict1: dict, typeDict2: dict) -> bool:
    return typeDict1["type"] == typeDict2["type"] and typeDict1["kind"] == typeDict2["kind"]


def intersectDicts(baseDict: dict, curDict: dict):
    return\
        {k: v for k, v in baseDict.items() if k in curDict and cmpTypes(curDict[k], v)},\
        {k: v for k, v in baseDict.items() if k not in curDict or not cmpTypes(curDict[k], v)},\
        {k: v for k, v in curDict.items() if k not in baseDict or not cmpTypes(baseDict[k], v)}


def main(base_file, specs_path, retry_flag):
    pwd = []
    if os.path.isdir(specs_path):
        specs_template = specs_path + \
                         ('' if specs_path.endswith('/') else '/') + '{}'
        files = (os.fsdecode(file) for file in os.listdir(os.fsencode(specs_path)))
        files = (file for file in files if not os.path.isdir(os.path.join(specs_path, file)))
        pwd = [specs_template.format(file) for file in files]
    else:
        pwd = [specs_path]

    parser = CParser()
    baseDict = {}
    with open(base_file, 'r') as reader:
        code = reader.read()
        baseDict = parser.squeezeCode(code)

    if retry_flag:
        repeater = myRepeater()

    for spec_file in pwd:
        code = ''
        with open(spec_file, "r") as reader:
            code = reader.read()
        parser = CParser()
        curDict = parser.squeezeCode(code)

        cmp = Comparator(baseDict, curDict)
        compare_res, compare_full, compare_miss, compare_extr, noSpec, \
            functions_extr, functions_miss, functions_noSpec, functions = cmp.getResult()

        filename = spec_file.rsplit('/', 1)[-1].rsplit('.', 1)[0]
        print(f"{filename}:\n" + \
              "    Similarity: {:.1f}%\n".format(compare_res) + \
              "\tFull Specifications: {:.1f}%\n".format(compare_full) + \
              "\tMissed Specifications: {:.1f}%\n".format(compare_miss) + \
              "\tExtra Specifications: {:.1f}%\n".format(compare_extr) + \
              "\tNo Specifications: {:.1f}%\n".format(noSpec) + \
              "\tTop extr functions: {:s}\n".format(', '.join(f'{key}: {value}' for key, value in functions_extr.items())) + \
              "\tTop miss functions: {:s}\n".format(', '.join(f'{key}: {value}' for key, value in functions_miss.items())) 
            #   + \
            #   "\tLess hit similarity: {:.1f}%".format(100 * sum(functions_lessHit.values()) / len(functions_lessHit.values()))
              )
        if retry_flag:
            repeater.update(compare_res, functions_noSpec + list(functions.keys()), filename)
        
        # for func, vals in functions.items():
        #     print(f"{func} - {vals}")
        #     print()

    if retry_flag:
        repeater.create(base_file)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Specifications Comparator')
    parser.add_argument('-b', '--base-path', default="./apps/data/allSpecs.c")
    parser.add_argument('-s', '--specs-path', default="./apps/data/specs")
    parser.add_argument('-r', '--retry', action="store_true")
    args = parser.parse_args()

    base_path = args.base_path
    specs_path = args.specs_path
    main(base_path, specs_path, args.retry)
