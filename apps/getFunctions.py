import argparse
from myParser import CParser
from myRepeater import myRepeater


def main(specPath: str, resDir: str, keywords: list[str], funcsPath: str, random: int):
    parser = CParser()
    code = ""
    with open(specPath, "r") as reader:
        code = reader.read()
    
    extrFilename = ""
    if keywords:
        extrFilename += "K"
    if funcsPath:
        extrFilename += "S"
    if random:
        extrFilename += "R"
    functions = parser.extract(code, keywords, funcsPath, random)

    filename = extrFilename + specPath.rsplit('/', 1)[-1].rsplit('.', 1)[0]

    repeater = myRepeater(resDir)
    repeater.create(functions.values(), filename)
    print(list(functions.keys()))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get functions from specifications')
    parser.add_argument('-s', '--spec-path', default="./apps/data/allSpecs.c")
    parser.add_argument('-o', '--output-dir', default="./apps/new/")
    parser.add_argument('-k', '--keywords', nargs='+', type=str)
    parser.add_argument('-f', '--functions-path')
    parser.add_argument('-r', '--random', type=int)
    args = parser.parse_args()

    specPath = args.spec_path
    resDir = args.output_dir
    keywords = args.keywords
    funcsPath = args.functions_path
    random = args.random
    main(specPath, resDir, keywords, funcsPath, random)