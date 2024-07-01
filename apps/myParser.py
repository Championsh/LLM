import re
import random
from tree_sitter import Language, Parser, Tree, Node


class myParser:
    def __init__(self, language: str, code_query: str, body_query: str, preproc_query: str, defines_query: str):
        Language.build_library('build/my-languages.so', ['../tree-sitter-' + language])
        self.language = Language('build/my-languages.so', language)
        self.parser = Parser()
        self.parser.set_language(self.language)
        self.code_query = code_query
        self.body_query = body_query
        self.preproc_query = preproc_query
        self.defines_query = defines_query
        self.functions = {}

    def __getTree(self, code: str) -> Tree:
        return self.parser.parse(
            bytes(code, "utf8")
        )

    def __parse(self, code: str, lvl: int) -> list: # Parse C code using Parser-levels
        # Get query for each level:
            # 0 - source code -> functions,
            # 1 - functions' body -> defines, calls, returns,
            # 2 - source code -> preprocess defines,
            # 3 - preprocess defines -> functions' body.
        lvlQueries = {
            0: self.code_query,
            1: self.body_query,
            2: self.preproc_query,
            3: self.defines_query
        }
        tree = self.__getTree(code)
        query = self.language.query(lvlQueries[lvl])
        return query.matches(tree.root_node)
    
    def __incFunctions(self, funcName: str, incType: str, **kwargs):
        # print(funcName)
        incTypes = {
            "dec": lambda val: self.functions[funcName].setdefault(val, []),
            "use": lambda args: [self.functions[funcName].setdefault(arg, []) for arg in args\
                                 if arg in self.functions[funcName]['param_types'] or arg == ''],
        }
        incTypes[incType](kwargs['var'])
        
        incActions = {
            "dec": lambda dict: self.functions[funcName]['param_types'].update({dict['var']: {"type": dict['type'], "kind": dict['kind']}}),
            "use": lambda dict: [self.functions[funcName][arg].append(dict['val']) for arg in dict['var']\
                                 if arg in self.functions[funcName]['param_types'] or arg == ''],
        }
        incActions[incType](kwargs)

    def __handleDeclartion(self, node: Node, funcName: str, declareKind: str):
        # Switch for declarators' type, which returns a tuple:
            # extra type symbols, declarator's name, (opt.) init value
        declTypes = {
            "identifier": lambda extr, x: (extr, x.text.decode()),
            # "pointer_declarator": lambda extr, x: (extr + '*', x.child_by_field_name("declarator").text.decode()),

            "pointer_declarator": lambda extr, x: (lambda res: (res[0] + extr, res[1]))((lambda val: declTypes[val.type]('*', val))(x.child_by_field_name("declarator"))),

            "init_declarator": lambda extr, x: (*(lambda res: (res[0] + extr, res[1]))((lambda val: declTypes[val.type]('', val))(x.child_by_field_name("declarator"))),
                                          x.child_by_field_name("value").text.decode()),
            "function_declarator": lambda extr, _: (extr, "None"),
            "array_declarator": lambda extr, x: (extr, x.child_by_field_name("declarator").text.decode()),
        }
        # Get declarator's type
        declType = node.child_by_field_name("type").text.decode()

        # Get node's declartor
        declarator = node.child_by_field_name("declarator")
        if not declarator:
            return
        # print(funcName, declarator.type)

        # Handle node according to it's type
        declRes = declTypes[declarator.type]('', declarator)
        extraType, declName, declVal = '', None, None
        if not declRes:
            return
        elif len(declRes) == 2:
            extraType, declName = declRes
        elif len(declRes) == 3:
            extraType, declName, declVal = declRes
        
        if not declName:
            return
        declType += extraType

        # Update functions dict according to handled node type
        self.__incFunctions(funcName, "dec", var=declName, type=declType, kind=declareKind)
        if declVal:
            self.__incFunctions(funcName, "use", var=[declName], val=("init", declVal))

    def __handleExpression(self, node: Node, funcName: str, _: str):
        calledFunc = node.child_by_field_name("function").text.decode()
        calledFuncArgs = node.child_by_field_name("arguments").children

        self.__incFunctions(funcName, "use", var=[''] if len(calledFuncArgs) == 2\
                            else [arg.text.decode() if arg.type == "identifier"
                                  else arg.child_by_field_name("argument").text.decode()
                                    for arg in calledFuncArgs 
                                        if arg.type == 'identifier' or arg.type == 'pointer_expression']
        , val=("call", calledFunc))

    def __handleReturn(self, node: Node, curDict: dict, _: str):
        pass
    
    def __handlePreproc(self, definitions: dict) -> dict:
        resDefinitions = {}
        for _, definition in definitions:
            def_name = definition['name'].text.decode()
            def_params = [param.text.decode() for param in definition['params'].named_children if param.text.decode() != 'void'] if 'params' in definition else []
            def_value = '\n'.join(list(val for val in map(str.strip, definition['value'].text.decode().split('\\')) if val))

            resDefinitions[def_name] = resDefinitions.setdefault(def_name, []) + [(def_params, def_value)]
        return resDefinitions
    
    def __handleCall(self, codeText: str, bodyCall: Node, curDef: list) -> str:
        funcName = bodyCall["name"].text.decode()
        oldNode = bodyCall["call"].text.decode()
        funcArgs = [param.text.decode() for param in bodyCall['args'].named_children] if 'args' in bodyCall else []

        newText = ''
        for defParams, defValue in curDef:
            if len(funcArgs) != len(defParams):
                continue

            newText = defValue
            for arg, param in zip(funcArgs, defParams):
                newText = newText.replace(param, arg)
            break
        if newText == '':
            print(f"Preproc call ERROR! {funcName}: {oldNode}, {curDef}")
            return codeText
        return codeText.replace(oldNode, newText)
    
    def __get_random_pairs(self, inputDict: dict, numPairs: int):
        if numPairs > len(inputDict) or not numPairs:
            return inputDict
        
        keys = list(inputDict.keys())
        randomKeys = random.sample(keys, numPairs)
        randomPairs = {key: inputDict[key] for key in randomKeys}
        return randomPairs

    def __check(self):
        def is_word(string):
            pattern = r"^[a-zA-Z0-9_]*$"
            return bool(re.match(pattern, string))
        alertTemp = "ALERT, check for {%s}: {%s}\n"
        
        for func in self.functions:
            for key, val in self.functions[func].items():
                if key == 'param_types':
                    if not val:
                        print(alertTemp % (func, self.functions[func]))
                        break
                elif not is_word(key):
                    print(alertTemp % (func, self.functions[func]))
                    break

    def squeezeCode(self, code: str) -> dict:
        action = {
            "decl": self.__handleDeclartion,
            "expr": self.__handleExpression,
            "ret": self.__handleReturn,
            "call": self.__handleCall,
        }

        # Init Preprocess Definitions dict
        definitions = self.__handlePreproc(self.__parse(code, 2))

        matches = self.__parse(code, 0)
        for _, func in matches:
            # Get function's name
            funcName = func['func.name'].text.decode()
            
            # Init Functions dict for current function
            self.functions.setdefault(funcName, {})
            self.functions[funcName].setdefault('param_types', {})

            # Get function's type
            # self.functions[funcName]["type"] = func['func.type'].text.decode()

            # Handle function declarator
            funcParams = []
            for param in func['func.params'].named_children:
                if param.type != "parameter_declaration" or param.text.decode() == 'void':
                    continue

                action["decl"](param, funcName, "p")
                funcParams += param.text.decode()

            bodyText = func['func.body'].text.decode()
            # Handle body calls
            bodyCalls = self.__parse(bodyText, 3)
            for _, bodyCall in bodyCalls:
                callFunc = bodyCall["name"].text.decode()
                if callFunc in definitions:
                    bodyText = action["call"](bodyText, bodyCall, definitions[callFunc])

            # Handle function body
            inMatches = self.__parse(bodyText, 1)
            for _, body in inMatches:
                node_type, node = list(body.items())[0]
                action[node_type](node, funcName, "d")
            
            # Uppend definitions with new function's one
            # definitions[funcName] = [(funcParams, bodyText)]

        # Check resulting functions correctness using "__check()" function
        # self.__check()
        return self.functions

    def extract(self, code: str, keywords: list[str], funcPath: str, random: int) -> dict[str, tuple]:
        def shapeFunctions(functions: list[str]) -> list[str]:
            functions = list(map(str.strip, functions))
            functions = [(function[:-1] if function.endswith(";") else function) for function in functions]
            return functions

        # Init Preprocess Definitions dict
        definitions = self.__handlePreproc(self.__parse(code, 2))
        
        # Handle functions to pick list
        functions = []
        if funcPath:
            with open(funcPath, "r") as reader:
                functions = shapeFunctions(reader.readlines())

        resFuncs = {}
        matches = self.__parse(code, 0)
        for _, func in matches:
            # Get function name
            funcName = func['func.name'].text.decode()

            if functions and not any(function.lower() == funcName.lower() for function in functions):
                continue

            # Get function prototype
            funcDecl = ', '.join(list(map(str.strip, func['func.declarator'].text.decode().split(','))))
            funcProto = func['func.type'].text.decode().strip() + ' ' + ' '.join(funcDecl.replace('\n', '').split())

            # Check for condition achievement
            if not keywords or any(keyword.lower() in funcName.lower() for keyword in keywords):
                bodyText = func['func.body'].text.decode()
                # Handle body calls
                bodyCalls = self.__parse(bodyText, 3)
                for _, bodyCall in bodyCalls:
                    callFunc = bodyCall["name"].text.decode()
                    if callFunc in definitions:
                        bodyText = self.__handleCall(bodyText, bodyCall, definitions[callFunc])
                resFuncs[funcName] = (funcProto, funcProto + ' ' + bodyText)
            
            # Get function's parameters
            # funcParams = [param.text.decode() for param in func['func.params'].named_children if param.text.decode() != 'void'] if 'func.params' in func else []

            # Uppend definitions with new function's one
            # definitions[funcName] = [(funcParams, bodyText)]
        return self.__get_random_pairs(resFuncs, random)


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
                (expression_statement (call_expression) @expr)
                (return_statement) @ret
            ])
            """
        preproc_query = """
            ([
                (preproc_function_def
                    name: (_) @name
                    parameters: (_) @params
                    value: (_) @value
                )
                (preproc_def
                    name: (_) @name
                    value: (_) @value
                )
            ])
            """
        defines_query = """
            (call_expression
                function: (_) @name
                arguments: (_) @args
            ) @call
            """
        super().__init__('c', code_query, body_query, preproc_query, defines_query)


if __name__ == '__main__':
    main()
