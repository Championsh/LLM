import os
import re
import argparse


def current_name_busy(name):
    return os.path.exists(name)


save_prompt_path = 'prompts/'
save_comments_path = 'comments/'
uniteRule_template_path = 'com-rules/unite_rules_template.txt'
genRule_template_path = 'com-rules/generate_rules_template.txt'
saveRule_path = 'com-rules/'


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


def get_protos(protos_pwd):
    f = open(protos_pwd, "r")
    protos = f.read()
    f.close()

    res = []
    if "#include" not in protos:
        protos = protos.split(';\n')
        for proto in protos:
            if not proto.rstrip():
                continue
            if proto.startswith('//'):
                continue
            res += [proto]
        return res

    protos = comment_remover(protos).split('\n')
    tmp = ''
    fl = False
    for line in protos:
        line = line.rstrip()
        if (line.startswith('typedef') or line.startswith('#include')
                or line.startswith('#define') or not line):
            continue
        if line == '{':
            res += [tmp.replace('  ', ' ').replace('( ', '(').replace(' )',')')]
            tmp = ''
            fl = True
            continue
        if fl:
            if '}' in line:
                fl = False
            continue
        tmp += str(line) + ' '
    for line in res:
        print(line)
        print()
    return


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
    prototypes = [x.replace('  ', '').replace(';', '') for x in prototypes]
    rules = get_rules(rules_path, rule_numbers)

    for prototype in prototypes:
        res = prompt.format(func_prototype=prototype, sca_rules=rules)

        text_file = open(next(prompt_id), "w")
        n = text_file.write(res)

        if n == len(res):
            print("Success! String written to text file.")
        else:
            print("Failure! String not written to text file.")

        text_file.close()


def parse():
    result = ''
    code = input("Enter lines of code:\n")
    while True:
        if code == '--':
            break

        code = code.strip(';\n\t ')
        if code:
            result += code + ', '
        code = input()
    print()
    print(result)


def unite_rules(rules_pwd):
    f = open(uniteRule_template_path, "r")
    template = f.read()
    f.close()
    f = open(rules_pwd, "r")
    rules = f.read()
    f.close()
    path, _, name = rules_pwd.rpartition('/')
    name = name.replace('.c', '.txt')
    text_file = open(saveRule_path + 'unite_' + name, "w")
    res = template.format(auto_gen_rules=rules)
    n = text_file.write(res)
    if n == len(res):
        print(f"Success! Prompt for rules unite written to {saveRule_path + 'unite_' + name}.")
    else:
        print("Failure! Prompt for rules unite not written to text file.")
    text_file.close()


def gen_rules(spec_pwd):
    f = open(genRule_template_path, "r")
    template = f.read()
    f.close()
    f = open(spec_pwd, "r")
    specs = f.read()
    f.close()
    path, _, name = spec_pwd.rpartition('/')
    name = name.replace('.c', '.txt')
    text_file = open(saveRule_path + '/' + 'genRules_' + name, "w")
    res = template.format(spec=specs)
    n = text_file.write(res)
    if n == len(res):
        print(f"Success! Prompt for rules generation written to {saveRule_path + '/' + 'genRules_' + name}.")
    else:
        print("Failure! Prompt for rules generation not written to text file.")
    text_file.close()


# def extract_comments(path):


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Spec Gen')
    parser.add_argument('-p', '--parse', action="store_true")
    parser.add_argument('-f', '--form', action="store_true")
    parser.add_argument('-tp', '--template-path', default="/home/champion/Projects/LLM/template.txt")
    parser.add_argument('-rp', '--rules-path', default="/home/champion/Projects/LLM/sg_rules")
    parser.add_argument('-pp', '--prototypes-path')
    parser.add_argument('-r', '--rule-numbers')
    parser.add_argument('-gr', '--gen-rules')
    parser.add_argument('-ur', '--unite-rules')
    # parser.add_argument('-sp', '--save-path', default="/home/champion/Projects/LLM/tmp/prompt{num}.txt")
    args = parser.parse_args()

    template_path = args.template_path
    rules_path = args.rules_path
    prototypes_path = args.prototypes_path
    rule_numbers = list(map(int, list(args.rule_numbers))) if args.rule_numbers else None
    spec_pwd = args.gen_rules
    rules_pwd = args.unite_rules
    # save_path = args.save_path

    if args.parse:
        parse()

    if args.form:
        form(template_path, rules_path, protos_path=prototypes_path, rule_numbers=rule_numbers)

    if spec_pwd:
        gen_rules(spec_pwd)

    if rules_pwd:
        unite_rules(rules_pwd)

