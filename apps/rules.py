import os
import re
import regex
import argparse


def current_name_busy(name):
    return os.path.exists(name)


save_prompt_path = './prompts/'
save_comments_path = './comments/'
uniteRule_template_path = './templates/unite_rules_template.txt'
genRule_template_path = './templates/generate_rules_template.txt'
save_rule_path = './templates/'
save_specs_path = './protos-auto/{}'


def gen_prompt_id():
    saveto = save_prompt_path + "prompt{num}.txt"

    while True:
        counter = 1
        cur_prompt_path = saveto.format(num=counter)
        while current_name_busy(cur_prompt_path):
            counter += 1
            cur_prompt_path = saveto.format(num=counter)
        yield cur_prompt_path


prompt_id = gen_prompt_id()


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


def squeeze_specs(specs_pwd: str):
    pwd = []
    if os.path.isdir(specs_pwd):
        specs_template = specs_pwd + \
                         ('' if specs_pwd.endswith('/') else '/') + '{}'
        files = (os.fsdecode(file) for file in os.listdir(os.fsencode(specs_pwd)))
        files = (file for file in files if not os.path.isdir(os.path.join(specs_pwd, file)))
        pwd = [specs_template.format(file) for file in files]
    else:
        pwd = [specs_pwd]

    for filename in pwd:
        f = open(filename, "r")
        text = f.read()
        f.close()
        specs = comment_remover(text)

        pattern = r"{(?:[^{}]|(?R))*}"
        res = regex.sub(pattern, ";", specs)

        text_file = open(save_specs_path.format(filename.rsplit('/')[-1]), "w")
        text_file.write(res.replace('( ', '(').replace(') ', ')'))

        text_file.close()


def get_protos(protos_pwd):
    f = open(protos_pwd, "r")
    protos = f.read()
    f.close()

    res = []
    protos = protos.split(';\n')
    for proto in protos:
        if not proto.rstrip():
            continue
        if proto.startswith('//'):
            continue
        res += [proto]
    return res


def get_rules(rules_pwd, rule_numbers):
    f = open(rules_pwd, "r")
    rules = list(filter(None, map(str.lstrip, f.read().split(';'))))
    f.close()

    if rule_numbers is None:
        return ''.join(rules)

    res = ''
    for rule in rules:
        if not rule.rstrip():
            continue
        num = rule.split('.')[0]

        if (int(num) if num.isdigit() else 0) in rule_numbers:
            res += rule + '\n'
    return res


def form(path, rules_path=None, protos_path=None, rule_numbers=None):
    f = open(path, "r")
    prompt = f.read()
    f.close()

    prototypes = get_protos(protos_path) if protos_path else [input("Enter the prototype of the function:\n")]
    prototypes = [x.replace('  ', '').replace(';', '').strip() for x in prototypes]
    rules = get_rules(rules_path, rule_numbers)

    res = prompt.format(func_prototype=', '.join(prototypes), sca_rules=rules)

    text_file = open(next(prompt_id), "w")
    n = text_file.write(res)

    if n == len(res):
        print(f"Success! String written to text file {text_file.name}.")
    else:
        print("Failure! String not written to text file.")

    text_file.close()


def show_progress(function, L):
    def wrapper(elem):
        i, x = elem
        print('{}/{}'.format(i, len(L)))
        return bool(function(x.strip()))
    return wrapper


def parse_scra(scra_pwd):
    f = open(scra_pwd, "r")
    scra = f.readlines()
    f.close()

    lib_names = []
    names = []
    protos = []
    presence_types = []

    name_filter = "include"
    proto_filter = "inline"
    presence_filter = "CONTAINS"

    for line in scra:
        tmp = line.split(';')
        if len(tmp) < 7:
            continue
        func_lib_name, func_name, func_proto, func_presence_type = tmp[2], tmp[4], tmp[5], tmp[-1].strip()
        lib_names += [func_lib_name]
        names += [func_name]
        protos += [func_proto]
        presence_types += [func_presence_type]
    
    protos_lib_pwd = "./protos/res_openssl"
    lib = open(protos_lib_pwd, "r")
    proto_names = lib.readlines()
    lib.close()
    proto_names = list(map(lambda s: s.strip(), proto_names))

    protos = [proto.strip() for proto, func_name, lib_name, presence_type in zip(protos, names, lib_names, presence_types)
                if func_name in proto_names and name_filter in lib_name and presence_type == presence_filter and proto_filter not in proto]
    
    pattern = re.compile("(const |).+? .+?\(.+?")
    res_protos = []
    for proto in protos:
        if pattern.match(proto.strip()):
            res_protos += [proto]
    protos = res_protos

    scra_protos_pwd = "usages/%s"
    path, _, name = scra_pwd.rpartition('/')

    scra_proto_file = open(scra_protos_pwd % name, "w")
    for proto in res_protos:
        scra_proto_file.write(proto + ';\n')
    scra_proto_file.close()


def unite_rules(rules_pwd):
    f = open(uniteRule_template_path, "r")
    template = f.read()
    f.close()
    f = open(rules_pwd, "r")
    rules = f.read()
    f.close()
    path, _, name = rules_pwd.rpartition('/')
    name = name.replace('.c', '.txt')
    text_file = open(save_rule_path + 'unite_' + name, "w")
    res = template.format(auto_gen_rules=rules)
    n = text_file.write(res)
    if n == len(res):
        print(f"Success! Prompt for rules unite written to {save_rule_path + 'unite_' + name}.")
    else:
        print("Failure! Prompt for rules unite not written to text file.")
    text_file.close()


def gen_rules_prompt(spec_pwd):
    f = open(genRule_template_path, "r")
    template = f.read()
    f.close()
    f = open(spec_pwd, "r")
    specs = f.read()
    f.close()
    path, _, name = spec_pwd.rpartition('/')
    name = name.rsplit('.', 1)[0] + '.txt'
    text_file = open(save_rule_path + '/' + 'genRules_' + name, "w")
    res = template.format(spec=specs)
    n = text_file.write(res)
    if n == len(res):
        print(f"Success! Prompt for rules generation written to {save_rule_path + '/' + 'genRules_' + name}.")
    else:
        print("Failure! Prompt for rules generation not written to text file.")
    text_file.close()


# def extract_comments(path):


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Spec Gen')
    parser.add_argument('-p', '--parse-scra')
    parser.add_argument('-f', '--form', action="store_true")
    parser.add_argument('-tp', '--template-path', default="./template.txt")
    parser.add_argument('-rp', '--rules-path', default="./spec-rules/simplified_rules")
    parser.add_argument('-pp', '--prototypes-path')
    parser.add_argument('-r', '--rule-numbers')
    parser.add_argument('-gr', '--gen-rules')
    parser.add_argument('-ur', '--unite-rules')
    parser.add_argument('-ss', '--squeeze-specs')

    # parser.add_argument('-sp', '--save-path', default="/home/champion/Projects/LLM/usages/prompt{num}.txt")
    args = parser.parse_args()

    parse_scra_path = args.parse_scra
    template_path = args.template_path
    rules_path = args.rules_path
    prototypes_path = args.prototypes_path
    rule_numbers = list(map(int, list(args.rule_numbers))) if args.rule_numbers else None
    gen_rules_pwd = args.gen_rules
    unite_rules_pwd = args.unite_rules
    # save_path = args.save_path
    squeeze_specs_pwd = args.squeeze_specs

    if parse_scra_path:
        parse_scra(parse_scra_path)

    if args.form:
        form(template_path, rules_path, protos_path=prototypes_path, rule_numbers=rule_numbers)

    if gen_rules_pwd:
        gen_rules_prompt(gen_rules_pwd)

    if unite_rules_pwd:
        unite_rules(unite_rules_pwd)

    if squeeze_specs_pwd:
        squeeze_specs(squeeze_specs_pwd)
