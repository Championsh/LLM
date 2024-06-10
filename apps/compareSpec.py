import os
import argparse
from tree_sitter import Language, Parser, Tree, Node


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

    def varMapping(self, baseDict: dict, curDict: dict) -> dict: # Get variables' values mappings
        intersection, baseDiff, curDiff = intersectDicts(baseDict, curDict)
        mapping = {k: k for k in intersection}
        mapping[''] = ''

        for baseKey, baseVal in baseDiff.items():
            for curKey, curVal in curDiff.items():
                if cmpTypes(baseVal, curVal):
                    mapping[baseKey] = curKey
                    del curDiff[curKey]
                    break
            if baseKey not in mapping:
                mapping[baseKey] = 'None'
        # print(baseDict)
        # print(curDict)
        # print(mapping)
        return mapping

        mapping = {'' : ''}
        for var in baseDict:
            if var in curDict and baseDict[var] == curDict[var]:
                mapping[var] = var
            elif baseDict[var] in curDict.values() and \
                    list(curDict.values()).count(baseDict[var]) > list(mapping.values()).count(baseDict[var]):
                var_choices = [param for param in curDict \
                                if curDict[param] == baseDict[var] and\
                                    param not in mapping.values()]
                if len(var_choices) == 0:
                    mapping[var] = 'None'
                else:
                    mapping[var] = var_choices[0]
            else:
                mapping[var] ='None'
        return mapping
        # print("Mapping: ", mapping)

    def incRes(self, funcRes: tuple):
        funcName, compFull, compMiss, compExtr, func = funcRes

        self.res += func["val"]
        self.compFull += compFull
        self.compMiss += compMiss
        self.compExtr += compExtr
        self.functions[funcName] = func
        # handle cur functions misses

    def cmpFunctions(self, funcName: str, baseFunc, curFunc) -> tuple:
        # print(funcName)
        # Get variables' values mappings
        mapping = self.varMapping(baseFunc['param_types'], curFunc['param_types'])

        # Get variables amount
        var_amount = len(baseFunc.keys()) - 1
        
        # Functions with 0 variables handle
        if var_amount == 0:
            self.res += 1
            self.noVar += [funcName]
            return

        # Init values
        var_res = 0
        var_compare_full = 0
        var_compare_miss = 0
        var_compare_extr = 0
        funcValues = {"miss": [], "extr": [], "hit": [], "val": 0}

        # print("baseFunc: ", baseFunc)
        # print("curFunc: ", curFunc)
        for var in baseFunc.keys():
            if var == 'param_types' or var == 'body':
                continue
            if mapping[var] == 'None':
                for func in baseFunc[var]:
                    self.topMiss[func] = self.topMiss.setdefault(func, 0) + 1
                    funcValues["miss"] += [func]
                var_compare_miss += 1
                continue
            
            # Get dicts for the current variable to compare
            baseVarFunctions, curVarFunctions = baseFunc[var], curFunc[mapping[var]]

            # If some function's var is not used in specifications
            var_functions_amount = len(baseVarFunctions)
            if var_functions_amount == 0:
                var_res += 1
                for func in curVarFunctions:
                    self.topExtr[func] = self.topExtr.setdefault(func, 0) + 1
                    funcValues["extr"] += [func]
                var_compare_extr += 1
                continue
            
            cur_var_functions_res = 0
            miss_fl, extr_fl = False, False
            # Get info about the missed functions
            for missFunction in list(set(baseVarFunctions).difference(curVarFunctions)):
                self.topMiss[missFunction] = self.topMiss.setdefault(missFunction, 0) + 1
                funcValues["miss"] += [missFunction]
                miss_fl = True

            # Get info about the extra functions
            for extrFunction in list(set(curVarFunctions).difference(baseVarFunctions)):
                self.topExtr[extrFunction] = self.topExtr.setdefault(extrFunction, 0) + 1
                funcValues["miss"] += [extrFunction]
                extr_fl = True

            # Increase according to intersection of the functions
            cur_var_functions_res += len(list(set(curVarFunctions) & set(baseVarFunctions)))

            # for baseVarFunction in baseVarFunctions:
            #     if baseVarFunction in curVarFunctions:
            #         cur_var_functions_res += 1
            #         curVarFunctions.remove(baseVarFunction) # TODO: Check squeezeCode for the need to "remove"
            #     else:
            #         self.topMiss[baseVarFunction] = self.topMiss.setdefault(baseVarFunction, 0) + 1
            #         funcValues["miss"] += [baseVarFunction]
                    
            
            tmp = cur_var_functions_res / var_functions_amount
            var_res += tmp
            if tmp == 1:
                var_compare_full += 1
            if miss_fl:
                var_compare_miss += 1
            if extr_fl:
                var_compare_extr += 1

        funcValues["val"] = var_res / var_amount
        return funcName,\
            var_compare_full / var_amount,\
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

            # Increase Result values according to the checked functions
            self.incRes(self.cmpFunctions(funcName, baseFunc, curFunc))

        return 100 * self.res / self.funcAmount,\
            100 * self.compFull / self.funcAmount,\
            100 * self.compMiss / self.funcAmount,\
            100 * self.compExtr / self.funcAmount,\
            100 * len(self.noSpec) / self.funcAmount,\
            dictSort(self.topExtr, self.outputLimit),\
            dictSort(self.topMiss, self.outputLimit),\
            self.noSpec[:self.outputLimit],\
            self.functions
            # dict(filter(lambda x: x[1]["val"] < 0.5 , sorted(self.functions.items(), key=lambda x: x[1]["val"])))


class Repeater:
    def __init__(self):
        self.value, self.repeat_functions, self.filename = .0, [], ""
    
    def update(self, value: float, repeat_functions: list[str], filename: str):
        if value > self.value:
            self.value = value
            self.repeat_functions = repeat_functions
            self.filename = filename
    
    def create(self, base_path: str):
        directory = './apps/new/'
        matches = []
        with open(base_path, 'r') as reader:
            baseCode = reader.read()
            matches = parseCode(baseCode)

        functions = {}
        for i in range(len(matches)):
            func = matches[i][1]

            func_name = func['func.name'].text.decode()
            functions[func_name] = {}
            functions[func_name]['proto'] = func['func.type'].text.decode() + ' ' + func['func.declarator'].text.decode()
            functions[func_name]['code'] = func['func'].text.decode()

        i = 0
        base_retry_path = directory + f"codes_{self.filename}.c"
        retry_codes_path = base_retry_path
        while(curNameBusy(retry_codes_path)):
            i += 1
            retry_codes_path = f'/{i}_'.join(base_retry_path.rsplit('/', 1))

        i = 0
        base_retry_path = directory + f"protos_{self.filename}.c"
        retry_protos_path = base_retry_path
        while(curNameBusy(retry_protos_path)):
            i += 1
            retry_protos_path = f'/{i}_'.join(base_retry_path.rsplit('/', 1))
        print(retry_protos_path)
        print(retry_codes_path)

        with open(retry_codes_path, 'w') as codes_writer:
            with open(retry_protos_path, 'w') as protos_writer:
                for func_name, func_info in functions.items():
                    if func_name not in self.repeat_functions:
                        continue
                    proto, code = func_info.values()
                    codes_writer.write(code + '\n\n')
                    protos_writer.write(proto + ';\n')

        return functions


    def __init__(self):
        queries = {
            'codeQuery': """
                // C# code query
                """,
            'bodyQuery': """
                // C# body query
                """
        }
        super().__init__('csharp', queries)


class myParser:
    def __init__(self, language: str, code_query: str, body_query: str):
        Language.build_library('build/my-languages.so', ['../tree-sitter-' + language])
        self.language = Language('build/my-languages.so', language)
        self.parser = Parser()
        self.parser.set_language(self.language)
        self.code_query = code_query
        self.body_query = body_query
        self.functions = {}

    def __getTree(self, code: str) -> Tree:
        return self.parser.parse(
            bytes(code, "utf8")
        )

    def __parse(self, code: str, is_code: bool = True) -> list:
        tree = self.__getTree(code)
        query = self.language.query(self.code_query if is_code else self.body_query)
        return query.matches(tree.root_node)
    
    def __incFunctions(self, funcName: str, incType: str, **kwargs):
        self.functions.setdefault(funcName, {})
        
        incTypes = {
            "dec": lambda _: self.functions[funcName].setdefault('param_types', {}),
            "use": lambda x: self.functions[funcName].setdefault(x, []),
        }
        try:
            incTypes[incType](kwargs['var'])
        except Exception:
            print(Exception)
        
        incActions = {
            "dec": lambda dict: self.functions[funcName]['param_types'].update({dict['var']: {"type": dict['type'], "kind": dict['kind']}}),
            "use": lambda x: self.functions[funcName].setdefault(x, []),
        }


    def __handleDeclartion(self, node: Node, funcName: str, declareKind: str):
        # Switch for declarators' type, which returns a tuple:
            # extra type symbols, declarator's name, (opt.) init value
        declTypes = {
            "identifier": lambda x: ('', x.text.decode()),
            "pointer_declarator": lambda x: ('*', x.child_by_field_name("declarator").text.decode()),
            "init_declarator": lambda x: (*declTypes[x.child_by_field_name("declarator").type](x.child_by_field_name("declarator")),
                                          x.child_by_field_name("value").text.decode()),
        }
        # Get declarator's type
        declType = node.child_by_field_name("type").text.decode()

        # Get node's declartor
        declarator = node.child_by_field_name("declarator")
        print(declarator.type)

        # Handle node according to it's type
        declRes = declTypes[declarator.type](declarator)
        extraType, declName, declVal = '', None, None
        if len(declRes) == 2:
            extraType, declName = declRes
        elif len(declRes) == 3:
            extraType, declName, declVal = declRes
        
        if not declName:
            return
        declType += extraType

        self.__incFunctions(self.functions[funcName], "dec", var=declName, type=declType, kind=declareKind)
        if declVal:
            self.__incFunctions(self.functions[funcName], "use", var=declName, type=declType, kind=declareKind)

        print(declType)
        print(declName)
        print(declVal)

    def __handleExpression(self, node: Node, curDict: dict):
        pass

    def __handleReturn(self, node: Node, curDict: dict):
        pass

    def __fillDict(self, func_name: str, node_type: str, node: Node):
        action = {
            "decl": self.__handleDeclartion,
            "expr": self.__handleExpression,
            "ret": self.__handleReturn
        }
        action[node_type](node, func_name)

        # try:
        #     action[node_type](self.functions[func_name], node)
        # except Exception:
        #     print(Exception)

    def squeezeCode(self, code: str) -> dict:
        matches = self.__parse(code)
        for _, func in matches:
            # Get function's name and Init dict with it
            func_name = func['func.name'].text.decode()
            self.functions[func_name] = {}
            self.functions[func_name][""] = []  # TODO: Remove this declarations without breaking the function
            # print(func_name)

            # Handle function declarator
            # print(func['func.params'].sexp())
            param_types = {}
            for param in func['func.params'].children:
                if param.type != "parameter_declaration" or param.child_by_field_name("declarator") is None:
                    continue
                param_type = param.child_by_field_name("type").text.decode()
                param_type += '' if param.child_by_field_name("declarator").type == "identifier" else param.child_by_field_name("declarator").child(0).text.decode()
                param_name = param.child_by_field_name("declarator").text.decode() if param.child_by_field_name("declarator").type == "identifier" else param.child_by_field_name("declarator").child(1).text.decode()
                # print(param_name)
                # print(param_type)
                param_types[param_name] = {"type": param_type, "kind": "p"}
                # param_types[param_name] = param_type
                self.functions[func_name][param_name] = []
            self.functions[func_name]['param_types'] = param_types

            # Handle function body
            print(func_name)
            inMatches = self.__parse(func['func.body'].text.decode(), False)
            # print(inMatches)
            for _, body in inMatches:
                node_type, node = list(body.items())[0]
                self.__fillDict(func_name, node_type, node)


            exit(1)
            # for param in func['func.body'].children:
            #     if param.type == "declaration":
            #         param_type = param.child_by_field_name("type").text.decode()
            #         param_type += '' if param.child_by_field_name("declarator").type == "identifier" else param.child_by_field_name("declarator").child(0).text.decode()
            #         param_name = param.child_by_field_name("declarator").text.decode() if param.child_by_field_name("declarator").type == "identifier" else param.child_by_field_name("declarator").child(1).text.decode()
            #         # print(param_name)
            #         # print(param_type)
            #         # if param_name == '=':
            #             # print(param.sexp())
            #         functions[func_name]['param_types'][param_name] = {"type": param_type, "kind": "d"}
            #         # functions[func_name]['param_types'][param_name] = param_type
            #         functions[func_name][param_name] = []

            #     elif param.type == "expression_statement":
            #         # print(param.sexp())
            #         if param.child(0).type == "call_expression":
            #             called_func = param.child(0).child_by_field_name("function").text.decode()
            #             called_func_arguments = param.child(0).child_by_field_name("arguments").children

            #             if len(called_func_arguments) == 2:
            #                 functions[func_name][""] = functions[func_name].setdefault("", []) + [called_func]

            #             for argument in called_func_arguments:
            #                 if argument.type != 'identifier' and argument.type != 'pointer_expression':
            #                     continue
            #                 argument_name = argument.text.decode() if argument.type == "identifier" else argument.child_by_field_name("argument").text.decode()
            #                 # print(argument.sexp())
            #                 # print(argument_name)
            #                 if argument_name in functions[func_name]['param_types']:
            #                     functions[func_name][argument_name] += [called_func]
                    
            #         else:
            #             pass

            #     elif param.type == "if_statement":
            #         pass
            # print(functions)
        return functions


class CParser(myParser):
    def __init__(self):
        code_query = """
            (function_definition
                type: (_) @func.type
                declarator:
                [
                    (pointer_declarator declarator: 
                        (function_declarator declarator: 
                            name: (identifier) @func.name
                            parameters: (_) @func.params
                        )
                    )
                    (function_declarator declarator: 
                        name: (identifier) @func.name
                        parameters: (_) @func.params
                    )
                ] @func.declarator
                body: (_) @func.body
                ) @func
            """
        body_query = """
            (compound_statement [
                (declaration) @decl
                (expression_statement) @expr
                (return_statement) @ret
            ])
            """
        super().__init__('c', code_query, body_query)


class JavaParser(myParser):
    def __init__(self):
        code_query = """
            // Java code query
            """
        body_query = """
            // Java body query
            """
        super().__init__('java', code_query, body_query)


class CSharpParser(myParser):
    def __init__(self):
        code_query = """
            // C# code query
            """
        body_query = """
            // C# body query
            """
        super().__init__('csharp', code_query, body_query)


def curNameBusy(name):
    return os.path.exists(name)


def dictSort(var: dict, amount: int = None):
    amount = len(var) if amount is None else amount
    return dict(sorted(var.items(), key=lambda x: x[1], reverse=True)[:amount])


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
        repeater = Repeater()

    for spec_file in pwd:
        code = ''
        with open(spec_file, "r") as reader:
            code = reader.read()
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
            repeater.update(compare_res, functions_noSpec + list(functions.keys()))

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
