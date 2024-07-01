import os
import argparse
from tree_sitter import Language, Parser


def parseCode(code: str) -> list:
    Language.build_library(
        'build/my-languages.so',
        [
            '../tree-sitter-c'
        ]
    )
    CPP_LANGUAGE = Language('build/my-languages.so', 'c')

    parser = Parser()
    parser.set_language(CPP_LANGUAGE)

    tree = parser.parse(
        bytes(code, "utf8")
    )

    func_query = CPP_LANGUAGE.query(
        """
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
    body: (compound_statement) @func.body) @func
    """)

    return func_query.matches(tree.root_node)


def squeezeCode(code: str) -> dict:
    matches = parseCode(code)
    functions = {}
    for i in range(len(matches)):
        func = matches[i][1]

        func_name = func['func.name'].text.decode()
        functions[func_name] = {}
        functions[func_name][""] = []  # TODO: Remove this declarations without breaking the function
        # print(func_name)
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
            param_types[param_name] = param_type
            functions[func_name][param_name] = []
        functions[func_name]['param_types'] = param_types

        # print(func['func.body'].sexp())
        for param in func['func.body'].children:
            if param.type == "declaration":
                param_type = param.child_by_field_name("type").text.decode()
                param_type += '' if param.child_by_field_name("declarator").type == "identifier" else param.child_by_field_name("declarator").child(0).text.decode()
                param_name = param.child_by_field_name("declarator").text.decode() if param.child_by_field_name("declarator").type == "identifier" else param.child_by_field_name("declarator").child(1).text.decode()
                # print(param_name)
                # print(param_type)
                functions[func_name]['param_types'][param_name] = param_type
                functions[func_name][param_name] = []
            elif param.type == "expression_statement":
                # print(param.sexp())
                if param.child(0).type == "call_expression":
                    called_func = param.child(0).child_by_field_name("function").text.decode()
                    called_func_arguments = param.child(0).child_by_field_name("arguments").children

                    if len(called_func_arguments) == 2:
                        functions[func_name][""] = functions[func_name].setdefault("", []) + [called_func]

                    for argument in called_func_arguments:
                        if argument.type != 'identifier' and argument.type != 'pointer_expression':
                            continue
                        argument_name = argument.text.decode() if argument.type == "identifier" else argument.child_by_field_name("argument").text.decode()
                        # print(argument.sexp())
                        # print(argument_name)
                        if argument_name in functions[func_name]['param_types']:
                            functions[func_name][argument_name] += [called_func]
                
                else:
                    pass

            elif param.type == "if_statement":
                pass
        # print(functions)
    return functions


def current_name_busy(name):
    return os.path.exists(name)


def createRetry(base_file: str, retryFunctions: list[str], retry_filename: str):
    directory = './apps/new/'
    matches = []
    with open(base_file, 'r') as reader:
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
    base_retry_path = directory + f"codes_{retry_filename}.c"
    retry_codes_path = base_retry_path
    while(current_name_busy(retry_codes_path)):
        i += 1
        retry_codes_path = f'/{i}_'.join(base_retry_path.rsplit('/', 1))

    i = 0
    base_retry_path = directory + f"protos_{retry_filename}.c"
    retry_protos_path = base_retry_path
    while(current_name_busy(retry_protos_path)):
        i += 1
        retry_protos_path = f'/{i}_'.join(base_retry_path.rsplit('/', 1))
    print(retry_protos_path)
    print(retry_codes_path)

    with open(retry_codes_path, 'w') as codes_writer:
        with open(retry_protos_path, 'w') as protos_writer:
            for func_name, func_info in functions.items():
                if func_name not in retryFunctions:
                    continue
                proto, code = func_info.values()
                codes_writer.write(code + '\n\n')
                protos_writer.write(proto + ';\n')

    return functions


def dictSort(var: dict, amount: int = None):
    amount = len(var) if amount is None else amount
    return dict(sorted(var.items(), key=lambda x: x[1], reverse=True)[:amount])


def compare(baseDict: dict, curDict: dict):
    extra_functions_amount = 5
    compare_full = 0
    compare_miss = 0
    compare_extr = 0
    top_miss = {}
    top_extr = {}
    no_spec = []
    func_results = {}

    functions_amount = len(baseDict)
    res = 0
    for funcName in baseDict:
        # print(funcName)
        if funcName not in curDict:
            no_spec += [funcName]
            continue
        baseFunc = baseDict[funcName]
        curFunc = curDict[funcName]

        mapping = {'' : ''}
        for var in baseFunc['param_types']:

            if var in curFunc['param_types'] and baseFunc['param_types'][var] == curFunc['param_types'][var]:
                mapping[var] = var
            elif baseFunc['param_types'][var] in curFunc['param_types'].values() and \
                    list(curFunc['param_types'].values()).count(baseFunc['param_types'][var]) > list(mapping.values()).count(baseFunc['param_types'][var]):
                var_choices = [param for param in curFunc['param_types'] \
                                if curFunc['param_types'][param] == baseFunc['param_types'][var] and\
                                    param not in mapping.values()]
                if len(var_choices) == 0:
                    mapping[var] = 'None'
                else:
                    mapping[var] = var_choices[0]
            else:
                mapping[var] ='None'
        # print("Mapping: ", mapping)

        var_amount = len(baseFunc.keys()) - 1
        if var_amount == 0:
            res += 1
            continue

        cur_var_res = 0
        var_compare_full = 0
        var_compare_miss = 0
        var_compare_extr = 0
        # print("baseFunc: ", baseFunc)
        # print("curFunc: ", curFunc)
        for var in baseFunc.keys():
            if var == 'param_types':
                continue
            if mapping[var] == 'None':
                for func in baseFunc[var]:
                    top_miss[func] = top_miss.setdefault(func, 0) + 1
                var_compare_miss += 1
                continue
                    
            baseVarFunctions = baseFunc[var]
            curVarFunctions = curFunc[mapping[var]]

            var_functions_amount = len(baseVarFunctions)
            if var_functions_amount == 0:
                cur_var_res += 1
                for func in curVarFunctions:
                    top_extr[func] = top_extr.setdefault(func, 0) + 1
                var_compare_extr += 1
                continue
            
            cur_var_functions_res = 0
            for baseVarFunction in baseVarFunctions:
                if baseVarFunction in curVarFunctions:
                    cur_var_functions_res += 1
                else:
                    top_miss[baseVarFunction] = top_miss.setdefault(baseVarFunction, 0) + 1
            
            tmp = cur_var_functions_res / var_functions_amount
            cur_var_res += tmp
            if tmp < 1:
                var_compare_miss += 1
            else:
                var_compare_full += 1
            
            extr_fl = False
            for curVarFunction in curVarFunctions:
                if curVarFunction not in baseVarFunctions:
                    extr_fl = True
                    top_extr[curVarFunction] = top_extr.setdefault(curVarFunction, 0) + 1
            if extr_fl:
                var_compare_extr += 1
        
        res += cur_var_res / var_amount
        compare_full += var_compare_full / var_amount
        compare_miss += var_compare_miss / var_amount
        compare_extr += var_compare_extr / var_amount
        
        func_results[funcName] = cur_var_res / var_amount

    return 100 * res / functions_amount,\
        100 * compare_full / functions_amount,\
        100 * compare_miss / functions_amount,\
        100 * compare_extr / functions_amount,\
        100 * len(no_spec) / functions_amount,\
        dictSort(top_extr, extra_functions_amount),\
        dictSort(top_miss, extra_functions_amount),\
        no_spec[:extra_functions_amount],\
        dict(filter(lambda x: x[1] < 0.5 , sorted(func_results.items(), key=lambda x: x[1])))


def main(base_file, specs_path):
    pwd = []
    if os.path.isdir(specs_path):
        specs_template = specs_path + \
                         ('' if specs_path.endswith('/') else '/') + '{}'
        files = (os.fsdecode(file) for file in os.listdir(os.fsencode(specs_path)))
        files = (file for file in files if not os.path.isdir(os.path.join(specs_path, file)))
        pwd = [specs_template.format(file) for file in files]
    else:
        pwd = [specs_path]

    baseDict = {}
    with open(base_file, 'r') as reader:
        code = reader.read()
        baseDict = squeezeCode(code)

    max_compare, max_retry_functions, max_filename = 0, [], ''
    for spec_file in pwd:
        code = ''
        with open(spec_file, "r") as reader:
            code = reader.read()
        curDict = squeezeCode(code)

        compare_res, compare_full, compare_miss, compare_extr, noSpec, \
            functions_extr, functions_miss, functions_noSpec, functions_lessHit = compare(baseDict, curDict)

        filename = spec_file.rsplit('/', 1)[-1].rsplit('.', 1)[0]
        print(f"{filename}:\n" + \
              "    Similarity: {:.1f}%\n".format(compare_res) + \
              "\tFull Specifications: {:.1f}%\n".format(compare_full) + \
              "\tMissed Specifications: {:.1f}%\n".format(compare_miss) + \
              "\tExtra Specifications: {:.1f}%\n".format(compare_extr) + \
              "\tNo Specifications: {:.1f}%\n".format(noSpec) + \
              "\tTop extr functions: {:s}\n".format(', '.join(f'{key}: {value}' for key, value in functions_extr.items())) + \
              "\tTop miss functions: {:s}\n".format(', '.join(f'{key}: {value}' for key, value in functions_miss.items())) + \
              "\tLess hit similarity: {:.1f}%".format((100 * sum(functions_lessHit.values()) / len(functions_lessHit.values())) if len(functions_lessHit.values()) else 100))
        if compare_res > max_compare:
            max_compare = compare_res
            max_retry_functions = functions_noSpec + list(functions_lessHit.keys())
            max_filename = filename
    createRetry(base_file, max_retry_functions, max_filename)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Specifications Comparator')
    parser.add_argument('-b', '--base-path', default="./apps/data/allSpecs.c")
    parser.add_argument('-s', '--specs-path', default="./apps/data/specs")
    args = parser.parse_args()

    base_path = args.base_path
    specs_path = args.specs_path
    main(base_path, specs_path)
