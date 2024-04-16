import os
import re
from collections import Counter


def comment_remover(text):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return " "  # note: a space and not an empty string
        else:
            return s

    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, text)


def extract_definitions(header_file):
    definitions = {'defines': {}, 'functions': [], 'structures': [], 'typedefs': [], 'simple_typedefs': []}
    with open(header_file, 'r') as file:
        lines = file.readlines()
        lines = comment_remover('\n'.join(lines)).split('\n')
        structure_block = False
        define_block = ''
        typedef_block = 0
        structure_name = None
        parenth_counter = 0
        structure_members = []
        for i, line in enumerate(lines):
            if 'define' in line:
                # match = re.match(r'#\s*define\s*(\w+)\s*([\(\)a-zA-Z0-9\_\|\ \\\*]*)', line)
                match = re.match(r'#\s*define\s*(\w+)\s*(.*)', line)
                if match:
                    var_name, data_type = match.groups()
                    data_type = data_type.strip(' \\')

                    if 'STACK_OF' == var_name or 'LHASH_OF' == var_name:
                        if var_name in definitions['defines']:
                            continue
                        definitions['defines'][var_name] = ['(TYPE) TYPE']
                    
                    elif line.endswith('\\'):
                        define_block = var_name

                    if var_name in definitions['defines']:
                        definitions['defines'][var_name].append(data_type)
                    else:
                        definitions['defines'][var_name] = [data_type]

            elif define_block:
                if not line.strip():
                    continue
                
                definitions['defines'][define_block][-1] += '\\\n\t' + line.strip()
                if not line.endswith('\\'):
                    define_block = ''

            elif line.startswith('typedef'):

                if ';' not in line:
                    definitions['typedefs'].append(line.strip())
                    if '{' in line:
                        typedef_block = 2
                        parenth_counter = 1
                    else:
                        typedef_block = 1
                else:
                    definitions['simple_typedefs'].append(line.strip())
            
            elif typedef_block:
                if not line.strip():
                    continue
                
                definitions['typedefs'][-1] += '\n\t' + line.strip()

                if '{' in line:
                    parenth_counter += 1
                if '}' in line:
                    parenth_counter -= 1

                if line.endswith(';'):
                    if (not parenth_counter) and typedef_block == 2 or typedef_block == 1:
                        typedef_block = 0
                        parenth_counter = 0


            elif (line.startswith('struct') or line.startswith('const struct')) and line.endswith(';'):
                match = re.match(r'struct\s+(\w+)\s*;', line)
                if match:
                    structure_name = match.group(1)
                    definitions['structures'].append((structure_name, []))

            elif (line.startswith('struct') or line.startswith('const struct')) and not line.endswith(';'):
                structure_block = True
                match = re.match(r'struct\s+(\w+)\s*{', line)
                if match:
                    structure_name = match.group(1)
                    structure_members = []

            elif structure_block:
                if line.startswith('}'):
                    structure_block = False
                    definitions['structures'].append((structure_name, structure_members))
                    structure_name = None
                    structure_members = []
                elif line.strip():          
                    structure_members.append(line.strip(' ;'))

            elif line.startswith('void') or line.startswith('int') or line.startswith('char') or line.startswith('double') or line.startswith('float') or line.startswith('long') or line.startswith('short') or line.startswith('unsigned') or line.startswith('signed') or line.startswith('bool'):
                if line.strip().endswith(';'):
                    definitions['functions'].append(line.strip())

    return definitions


def write_to_global_header(definitions, global_header_file):
    with open(global_header_file, 'w') as file:
        # Write structure typedefs
        file.write('// Structure Typedefs\n')
        for structure_name, members in definitions['structures']:
            file.write(f'typedef struct {structure_name} {structure_name};\n\n')

        # Write defines
        file.write('// Defines\n')
        for var_name, data_types in definitions['defines'].items():
            # file.write(f'// {var_name}\n')

            file.write(f'#define {var_name} {data_types[0]}\n')
            file.write('\n')
        
        # Write simple Typedefs
        file.write('// Simple Typedefs\n')
        for typedef in sorted(definitions['simple_typedefs'], key=lambda type: 'typedef struct' not in type):
            # file.write(f'// {typedef_name}\n')
            file.write(f'{typedef}\n')
            file.write('\n')

        # Write structures
        file.write('// Structures\n')
        for structure_name, members in definitions['structures']:
            file.write(f'struct {structure_name} {{\n')
            for member in members:
                if any(preproc in member for preproc in ['if', 'ifdef', 'ifndef', 'endif', 'else', 'elif']):
                    file.write(f'    {member}\n')
                else:
                    file.write(f'    {member};\n')
            file.write('};\n\n')

        # Write typedefs
        file.write('// Typedefs\n')
        for typedef in definitions['typedefs']:
            # file.write(f'// {typedef_name}\n')
            file.write(f'{typedef}\n')
            file.write('\n')

        # Write functions
        file.write('// Functions\n')
        for function in definitions['functions']:
            file.write(f'{function}\n')


def main():
    directory = '/mnt/f/openssl/include/openssl'
    global_header_file = 'megaHeader2.h'

    all_definitions = {'defines': {}, 'functions': [], 'structures': [], 'typedefs': [], 'simple_typedefs': []}

    for filename in os.listdir(directory):
        if filename.endswith('.h') or filename.endswith('.h.in'):
            header_file = os.path.join(directory, filename)
            definitions = extract_definitions(header_file)

            for var_name, data_types in definitions['defines'].items():
                if var_name in all_definitions['defines']:
                    all_definitions['defines'][var_name].extend(data_types)
                else:
                    all_definitions['defines'][var_name] = data_types

            all_definitions['functions'].extend(definitions['functions'])
            all_definitions['structures'].extend(definitions['structures'])
            all_definitions['typedefs'].extend(definitions['typedefs'])
            all_definitions['simple_typedefs'].extend(definitions['simple_typedefs'])

    for var_name, data_types in definitions['defines'].items():
        definitions['defines'][var_name] = Counter(data_types).most_common(1)[0][0]

    write_to_global_header(all_definitions, global_header_file)


if __name__ == '__main__':
    main()
