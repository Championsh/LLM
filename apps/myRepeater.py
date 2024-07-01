import os


class myRepeater:
    def __init__(self, resDir: str = "./apps/new/"):
        self.value = .0
        self.repeatFuncs = []
        self.filename = ""
        self.resDir = resDir + "" if resDir.endswith("/") else "/"

    def __curNameBusy(self, name):
        return os.path.exists(name)
    
    def __getPath(self) -> tuple:
        i = 0
        retryPath = self.resDir + f"%d_{self.filename}_%s.c"
        retryCodesPath = retryPath % (i, "codes")
        retryProtsPath = retryPath % (i, "prots")
        while(self.__curNameBusy(retryCodesPath) or self.__curNameBusy(retryProtsPath)):
            i += 1
            retryCodesPath = retryPath % (i, "codes")
            retryProtsPath = retryPath % (i, "prots")
        return retryCodesPath, retryProtsPath
    
    def __getPath(self, filename: str) -> tuple:
        i = 0
        retryPath = self.resDir + f"%d_{filename}_%s.c"
        retryCodesPath = retryPath % (i, "codes")
        retryProtsPath = retryPath % (i, "prots")
        print(retryCodesPath)
        while(self.__curNameBusy(retryCodesPath) or self.__curNameBusy(retryProtsPath)):
            i += 1
            retryCodesPath = retryPath % (i, "codes")
            retryProtsPath = retryPath % (i, "prots")
        return retryCodesPath, retryProtsPath
    
    def update(self, value: float, repeatFuncs: list[str], filename: str):
        if value > self.value:
            self.value = value
            self.repeatFuncs = repeatFuncs
            self.filename = filename
    
    def create(self, basePath: str):
        from myParser import CParser

        parser = CParser()
        with open(basePath, 'r') as reader:
            functions = parser.extract(reader.read())
        functions = [value for name, value in functions.items() if (name in self.repeatFuncs if self.repeatFuncs else True)]

        retryCodesPath, retryProtsPath = self.__getPath()
        with open(retryCodesPath, 'w') as codesWriter:
            with open(retryProtsPath, 'w') as protsWriter:
                for funcInfo in functions.items():
                    proto, code = funcInfo.values()
                    codesWriter.write(code + '\n\n')
                    protsWriter.write(proto + ';\n')
        return functions
    
    def create(self, functions: list[(str, str)], filename: str):
        retryCodesPath, retryProtsPath = self.__getPath(filename)
        with open(retryCodesPath, 'w') as codesWriter:
            with open(retryProtsPath, 'w') as protsWriter:
                for proto, code in functions:
                    codesWriter.write(code + '\n\n')
                    protsWriter.write(proto + ';\n')