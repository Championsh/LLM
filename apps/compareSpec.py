import os
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

    # parsing a string of code
    # tree = parser.parse(
    #     bytes(
    #         """
    # void *
    # AllocateAlignedReservedPages (
    # uintptr_t  Pages,
    # uintptr_t  Alignment
    # )
    # {
    # sf_set_trusted_sink_int(Pages);

    # void *Res;
    # uintptr_t Remainder;

    # sf_overwrite(&Res);
    # sf_overwrite(Res);
    # sf_new (Res, ALIGNED_MEMORY_CATEGORY);
    # sf_set_possible_null(Res);
    # sf_not_acquire_if_eq(Res, Res, 0);

    # Remainder = (Pages * EFI_PAGE_SIZE) % Alignment;
    # if (Remainder == 0) {
    #     sf_buf_size_limit(Res, Pages * EFI_PAGE_SIZE);
    # } else {
    #     sf_buf_size_limit(Res, ((Pages * EFI_PAGE_SIZE) / Alignment + 1) * Alignment);
    # }

    # return Res;
    # }
            
    # XIDeviceInfo* XIQueryDevice(Display *display,
    #                             int deviceid,
    #                             int *ndevices_return) {
    #     XIDeviceInfo *res;
    #     sf_overwrite(&res);
    #     sf_overwrite(res);
    #     //sf_uncontrolled_value(res);
    #     //sf_set_possible_null(res);
    #     sf_bitinit(ndevices_return);
    #     sf_handle_acquire(res, X11_DEVICE);
    #     return res;
    # }

    # struct Colormap *XListInstalledColormaps(Display *display, Window w, int *num_return) {
    #     struct Colormap *res;
    #     sf_overwrite(&res);
    #     sf_overwrite(res);
    #     //sf_uncontrolled_value(res);
    #     //sf_set_possible_null(res);
    #     sf_handle_acquire(res, X11_CATEGORY);
    #     return res;
    # }

    # int XRemoveHost(Display* dpy, XHostAddress* host)
    # {
    # sf_use(host);
    # }
    # """,
    #         "utf8",
    #     )
    # )

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


def compare(baseDict, curDict):
    try:
        functions_amount = len(baseDict)

        res = 0
        for func in baseDict:
            # print(func)
            if func not in curDict.keys():
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
            # print("baseFunc: ", baseFunc)
            # print("curFunc: ", curFunc)
            for var in baseFunc.keys():
                if var == 'param_types' or mapping[var] == 'None':
                    continue
                baseVarFunctions = baseFunc[var]
                curVarFunctions = curFunc[mapping[var]]

                var_functions_amount = len(baseVarFunctions)
                if var_functions_amount == 0:
                    cur_var_res += 1
                    continue

                cur_var_functions_res = 0
                for baseVarFunction in baseVarFunctions:
                    if baseVarFunction in curVarFunctions:
                        cur_var_functions_res += 1
                cur_var_res += cur_var_functions_res / var_functions_amount
            
            res += cur_var_res / var_amount
        return "{:.1f}".format(100 * res / functions_amount)
    except Exception as e:
        print('Error occured: ', e)
    return 0


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

        print(filename, " similarity is ", compare(baseDict, curDict), "%")


if __name__ == '__main__':
    main()
