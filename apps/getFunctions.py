import os
from tree_sitter import Language, Parser

def main():
    directory = './c-spec'
    codes_file = './apps/data/allSpecs.c'
    protos_file = './apps/data/allProtos.c'

    Language.build_library(
        'build/my-languages.so',
        [
            '../tree-sitter-c'
        ]
    )
    CPP_LANGUAGE = Language('build/my-languages.so', 'c')

    parser = Parser()
    parser.set_language(CPP_LANGUAGE)
    
    res_functions = {}
    for filename in os.listdir(directory):
        spec_file = os.path.join(directory, filename)
        if os.path.isdir(spec_file):
            continue

        code = ''
        with open(spec_file, "r") as reader:
            code = reader.read()

        tree = parser.parse(bytes(code,"utf-8"))
        root_node = tree.root_node
        cur_functions = []
        code = code.split("\n")
        for child_node in root_node.children:
            if child_node.type == "function_definition":
                function_start_line = child_node.start_point[0]
                function_end_line = child_node.end_point[0]

                if function_start_line != function_end_line:
                    func_code = code[function_start_line:function_end_line + 1]
                    func_code = "\n".join(func_code)
                else:
                    func_code = code[function_start_line]

                declarator = child_node.child_by_field_name("declarator")
                if declarator.child(0).type != "identifier":
                    declarator = declarator.child_by_field_name("declarator")

                func_name = declarator.child_by_field_name("declarator").text.decode()
                func_declarator = child_node.child_by_field_name("type").text.decode()
                func_declarator = ('' if child_node.child(0).type == "type" else child_node.child(0).text.decode()) + func_declarator
                func_prototype = declarator.text.decode()

                cur_functions += [(func_name, func_code, func_prototype)]
        
        for func_name, func_code, func_prototype in cur_functions:
            if func_name in res_functions:
                res_functions[func_name].extend((func_code, func_prototype))
            else:
                res_functions[func_name] = [(func_code, func_prototype)]
    
    with open(codes_file, 'w') as codes_writer:
        with open(protos_file, 'w') as protos_writer:
            for func_name, func_array in res_functions.items():
                if len(func_array) != 1:
                    print(func_name)
                    continue
                func_code, func_prototype = func_array[0]
                
                codes_writer.write(func_code + '\n\n')
                protos_writer.write(func_prototype + ';\n')


if __name__ == '__main__':
    main()
