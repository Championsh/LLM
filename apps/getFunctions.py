import argparse
from myParser import CParser
from myRepeater import myRepeater


def main(spec_path: str, keywords: list[str], res_dir: str, functions_path: str, random: int):
    parser = CParser()
    code = ""
    with open(spec_path, "r") as reader:
        code = reader.read()
    
    extrFilename = ""
    if keywords:
        extrFilename += "K"
    if functions_path:
        extrFilename += "S"
    if random:
        extrFilename += "R"
    functions = parser.extract(code, keywords, functions_path, random)

    filename = extrFilename + spec_path.rsplit('/', 1)[-1].rsplit('.', 1)[0]

    repeater = myRepeater(res_dir)
    repeater.create(functions.values(), filename)
    print(list(functions.keys()))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get functions from specifications with certain keywords')
    parser.add_argument('-s', '--spec-path', default="./apps/data/allSpecs.c")
    parser.add_argument('-o', '--output-dir', default="./apps/new/")
    parser.add_argument('-k', '--keywords', nargs='+', type=str)
    parser.add_argument('-f', '--functions-path')
    parser.add_argument('-r', '--random', type=int)
    args = parser.parse_args()

    spec_path = args.spec_path
    res_dir = args.output_dir
    keywords = args.keywords
    functions_path = args.functions_path
    random = args.random
    main(spec_path, keywords, res_dir, functions_path, random)