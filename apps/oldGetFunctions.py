import os
import re
from tree_sitter import Language, Parser


def extractAlerts(bodyTree) -> list:
    alerts = []
    for param in bodyTree.children:
        if param.type == "declaration":
            declareValue = param.child_by_field_name("declarator").child_by_field_name("value")
            if declareValue is None or declareValue.type != 'call_expression':
                declareValue = ''
            else:
                declareValue = declareValue.child_by_field_name("function").text.decode()
            declareValue = declareValue.lower()
            if declareValue != '' and 'sf_' not in declareValue:
                alerts += [declareValue]
        elif param.type == "expression_statement":
            if param.child(0).type == "call_expression":
                called_func = param.child(0).child_by_field_name("function").text.decode()
                called_func = called_func.lower()
                if 'sf_' not in called_func:
                    alerts += [called_func]
            else:
                pass

        elif param.type == "if_statement":
            pass
    return alerts if len(alerts) else None


def codeReplace(codeText, oldNode, definitions):
    funcName = oldNode.child_by_field_name("function").text.decode() if oldNode.type == "call_expression" else oldNode.text.decode()
    funcArgs = oldNode.child_by_field_name("arguments").children if oldNode.type == "call_expression" else []

    offset: str = ' ' * int(oldNode.start_point[1])
    print(oldNode.text.decode())
    newText = ''
    for def_params, def_value in definitions[funcName]:
        if len(def_params) == 1 and def_params[0] == '' and len(funcArgs) == 0:
            newText = def_value
            break
        if len(funcArgs) != len(def_params):
            continue

        newText: str = def_value
        for arg, param in zip(funcArgs, def_params):
            newText = newText.replace(param, arg.text.decode())
        break
    if newText == '':
        print(funcName, ': ERROR')
        return codeText
    return codeText.replace(oldNode.text.decode(), f'\n{offset}'.join(newText.split('\n')))


def transformBody(bodyTree, definitionsTree) -> str:
    definitions = {}
    for definition in definitionsTree:
        definition = definition[1]
        def_name = definition['def.name'].text.decode()
        def_params = [param.text.decode() for param in definition['def.params'].children] if 'def.params' in definition else ['']
        def_value = '\n'.join(list(val for val in map(str.strip, definition['def.value'].text.decode().split('\\')) if val))

        if def_name in definitions:
            print(f"REPEAT DEF: {def_name}")
        definitions[def_name] = definitions.setdefault(def_name, []) + [(def_params, def_value)]
    print(definitions)

    bodyText: str = bodyTree.text.decode()
    for childNode in bodyTree.children:
        if childNode.type == "declaration":
            pass

        elif childNode.type == "expression_statement":
            oldNode = childNode.child(0)
            if oldNode.type == "call_expression":
                funcName = oldNode.child_by_field_name("function").text.decode()
                if funcName in definitions:
                    bodyText = codeReplace(bodyText, oldNode, definitions)
            else:
                pass

        elif childNode.type == "if_statement":
            pass
        
        else:
            if childNode.text.decode() in definitions:
                bodyText = codeReplace(bodyText, childNode, definitions)
    return bodyText


def parseCode(code: str) -> tuple:
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
    declarator: (_) @func.declarator
    body: (_) @func.body)
    """)
    functions = func_query.matches(tree.root_node)

    def_query = CPP_LANGUAGE.query(
        """
    ([
        (preproc_function_def
            name: (_) @def.name
            parameters: (_) @def.params
            value: (_) @def.value
        )
        (preproc_def
            name: (_) @def.name
            value: (_) @def.value
        )
    ])
    """)
    definitions = def_query.matches(tree.root_node)

    return (functions, definitions)


def main():
    directory = './specs/c-spec'
    codes_file = './apps/data/allSpecs.c'
    protos_file = './apps/data/allProtos.c'

    res_functions = {}
    alert_functions = {}
    for filename in os.listdir(directory):
        spec_file = os.path.join(directory, filename)
        if os.path.isdir(spec_file):
            continue

        code = ''
        with open(spec_file, "r") as reader:
            code = reader.read()

        functions, definitions = parseCode(code)
        for i in range(len(functions)):
            func = functions[i][1]
            declarator = func['func.declarator']
            if declarator.child(0).type != "identifier":
                declarator = declarator.child_by_field_name("declarator")
            func_name = declarator.child_by_field_name("declarator").text.decode()

            func_declarator = ', '.join(list(map(str.strip, func['func.declarator'].text.decode().split(','))))
            func_head = func['func.type'].text.decode().strip() + ' ' + ' '.join(func_declarator.replace('\n', '').split())
            func_body = transformBody(func['func.body'], definitions)
            # func_body = func['func.body'].text.decode()
            res_functions[func_name] = res_functions.setdefault(func_name, []) + [(func_head, func_head + ' ' + func_body)]
            alert_functions[func_name] = extractAlerts(func['func.body'])
    
    with open(codes_file, 'w') as codes_writer:
        with open(protos_file, 'w') as protos_writer:
           for func_name, func_codes in res_functions.items():
                if len(func_codes) != 1:
                    print(func_name)
                    continue
                func_proto, func_code = func_codes[0]
                
                # codes_writer.write(func_code + '\n\n')
                # protos_writer.write(func_proto + ';\n')

    for func_name, func_alerts in alert_functions.items():
        if func_alerts is None:
            continue
        print(func_name, ': ', func_alerts, '\n')


if __name__ == '__main__':
    main()
