import os
import argparse


def current_name_busy(name):
    return os.path.exists(name)


save_prompt_path = './tmp/'


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


def get_protos(protos_pwd):
    f = open(protos_pwd, "r")
    protos = f.read().split(';\n')

    res = []
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

    if not rule_numbers:
        rule_numbers = [i for i in range(1, int(rules[-1].split('.')[0]) + 1)]

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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Spec Gen')
    parser.add_argument('-p', '--parse', action="store_true")
    parser.add_argument('-f', '--form', action="store_true")
    parser.add_argument('-tp', '--template-path', default="/home/champion/Projects/LLM/template.txt")
    parser.add_argument('-rp', '--rules-path', default="/home/champion/Projects/LLM/sg_rules")
    parser.add_argument('-pp', '--prototypes-path')
    parser.add_argument('-r', '--rule-numbers')
    # parser.add_argument('-sp', '--save-path', default="/home/champion/Projects/LLM/tmp/prompt{num}.txt")
    args = parser.parse_args()

    template_path = args.template_path
    rules_path = args.rules_path
    prototypes_path = args.prototypes_path
    rule_numbers = list(map(int, list(args.rule_numbers)))
    # save_path = args.save_path

    if args.parse:
        parse()

    if args.form:
        form(template_path, rules_path, protos_path=prototypes_path, rule_numbers=rule_numbers)

