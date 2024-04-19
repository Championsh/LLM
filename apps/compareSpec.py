import os
from collections import Counter
from tree_sitter import Language, Parser


def transformCode(code):
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
    ]
    body: (compound_statement) @func.body)
    """)

    matches = func_query.matches(tree.root_node)
    functions = {}
    for i in range(len(matches)):
        func = matches[i][1]

        func_name = func['func.name'].text.decode()
        functions[func_name] = {}
        functions[func_name][""] = []
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
                        functions[func_name][''] += [called_func]

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


def dictSort(var, amount=None):
    amount = len(var) if amount is None else amount
    return dict(sorted(var.items(), key=lambda x: x[1], reverse=True)[:amount])


def compare(baseDict, curDict):
    # try:
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
    for func in baseDict:
        # print(func)
        if func not in curDict.keys():
            no_spec += [func]
            continue
        baseFunc = baseDict[func]
        curFunc = curDict[func]

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
                    if func not in top_miss.keys():
                        top_miss[func] = 1
                    else:
                        top_miss[func] += 1
                var_compare_miss += 1
                continue
                    
            baseVarFunctions = baseFunc[var]
            curVarFunctions = curFunc[mapping[var]]

            var_functions_amount = len(baseVarFunctions)
            if var_functions_amount == 0:
                cur_var_res += 1
                for func in curVarFunctions:
                    if func not in top_extr.keys():
                        top_extr[func] = 1
                    else:
                        top_extr[func] += 1
                var_compare_extr += 1
                continue
            
            cur_var_functions_res = 0
            for baseVarFunction in baseVarFunctions:
                if baseVarFunction in curVarFunctions:
                    cur_var_functions_res += 1
                else:
                    if baseVarFunction not in top_miss.keys():
                        top_miss[baseVarFunction] = 1
                    else:
                        top_miss[baseVarFunction] += 1
            
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
                    if curVarFunction not in top_extr.keys():
                        top_extr[curVarFunction] = 1
                    else:
                        top_extr[curVarFunction] += 1
            if extr_fl:
                var_compare_extr += 1
        
        res += cur_var_res / var_amount
        compare_full += var_compare_full / var_amount
        compare_miss += var_compare_miss / var_amount
        compare_extr += var_compare_extr / var_amount
        
        func_results[func] = cur_var_res / var_amount

    return 100 * res / functions_amount,\
        100 * compare_full / functions_amount,\
        100 * compare_miss / functions_amount,\
        100 * compare_extr / functions_amount,\
        100 * len(no_spec) / functions_amount,\
        dictSort(top_extr, extra_functions_amount),\
        dictSort(top_miss, extra_functions_amount),\
        no_spec[:extra_functions_amount],\
        dict(filter(lambda x: x[1] < 0.5 , sorted(func_results.items(), key=lambda x: x[1])))

    # return "Similarity: {:.1f}%\n".format(100 * res / functions_amount) + \
    #         "\tFull Specifications: {:.1f}%\n".format(100 * compare_full / functions_amount) + \
    #         "\tMissed Specifications: {:.1f}%\n".format(100 * compare_miss / functions_amount) + \
    #         "\tExtra Specifications: {:.1f}%\n".format(100 * compare_extr / functions_amount) + \
    #         "\tNo Specifications: {:.1f}%\n".format(100 * len(no_spec) / functions_amount) + \
    #         "\tTop extr functions: {:s}".format(', '.join(f'{key}: {value}' for key, value in dict(sorted(top_extr.items(), key=lambda x: x[1], reverse=True)[:extra_functions_amount]).items()) + \
    #         "\n\tTop miss functions: {:s}".format(', '.join(f'{key}: {value}' for key, value in dict(sorted(top_miss.items(), key=lambda x: x[1], reverse=True)[:extra_functions_amount]).items()))) + \
    #         "\n\tNo spec functions: {:s}".format(', '.join(no_spec[:extra_functions_amount])) + \
    #         "\n\tLess Hit: {:s}".format(', '.join(f'{key}' for key in dict(filter(lambda x: x[1] < 0.5 , sorted(func_results.items(), key=lambda x: x[1]))).keys()))
            
                
    # except Exception as e:
    #     print('Error occured: ', e)
    # return 0


def main():
    directory = './apps/data/specs'
    base_file = './apps/data/allSpecs.c'

    baseDict = {}
    with open(base_file, 'r') as reader:
        code = reader.read()
        baseDict = transformCode(code)

    for filename in os.listdir(directory):
        spec_file = os.path.join(directory, filename)
        if os.path.isdir(spec_file):
            continue

        code = ''
        with open(spec_file, "r") as reader:
            code = reader.read()
        curDict = transformCode(code)

        compare_res, compare_full, compare_miss, compare_extr, noSpec, \
            functions_extr, functions_miss, functions_noSpec, functions_lessHit = compare(baseDict, curDict)

        print(f"{filename}:\n" + \
              "Similarity: {:.1f}%\n".format(compare_res) + \
              "\tFull Specifications: {:.1f}%\n".format(compare_full) + \
              "\tMissed Specifications: {:.1f}%\n".format(compare_miss) + \
              "\tExtra Specifications: {:.1f}%\n".format(compare_extr) + \
              "\tNo Specifications: {:.1f}%\n".format(noSpec) + \
              "\tTop extr functions: {:s}".format(', '.join(f'{key}: {value}' for key, value in functions_extr.items())) + \
              "\n\tTop miss functions: {:s}".format(', '.join(f'{key}: {value}' for key, value in functions_miss.items())) + \
              "\n\tNo spec functions: {:s}".format(', '.join(functions_noSpec)))


if __name__ == '__main__':
    main()
