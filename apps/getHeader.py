import argparse, os
from myParser import CParser


def switch(specPath: str) -> tuple:
    code = ""
    resPath = specPath
    if os.path.isdir(specPath):
        resPath = "specsDir"
        for filename in os.listdir(specPath):
            newFilename = os.path.join(specPath, filename)
            if os.path.isdir(newFilename):
                continue
            with open(newFilename, "r") as reader:
                code += reader.read()
    else:
        resPath = resPath.rsplit('/', 1)[-1].rsplit('.', 1)[0]
        with open(specPath, "r") as reader:
            code = reader.read()
    return resPath, code


def main(specPath: str, resDir: str):
    parser = CParser()
    resPath, code = switch(specPath)
    heads = parser.head(code)["resCode"]

    filename = "H_" + resPath
    resDir = resDir + ("" if resDir.endswith("/") else "/")
    with open(resDir + filename, 'w') as writer:
        writer.write(heads)

if __name__ == '__main__':
    baseSpecPath = "./apps/data/allSpecs.c"
    baseSpecDir = "./specs/c-spec/"
    parser = argparse.ArgumentParser(description='Get typedefs from specifications')
    parser.add_argument('-s', '--spec-path', default=baseSpecPath)
    parser.add_argument('-d', '--spec-dir', default=baseSpecDir)
    parser.add_argument('-o', '--output-dir', default="./apps/new/")
    args = parser.parse_args()

    specPath = args.spec_path
    resDir = args.output_dir
    specDir = args.spec_dir
    if specDir != baseSpecDir or (baseSpecDir == baseSpecDir and specPath == baseSpecPath):
        main(specDir, resDir)
    else:
        main(specPath, resDir)