import os
import re
import json


def extract_substrings(text):
    if "```" not in text:
        return text

    pattern2 = r"\d\.\s(.*?```c.*?```)"
    matches2 = re.findall(pattern2, text, re.DOTALL | re.MULTILINE)

    if len(matches2) == 0:
        pattern1 = r"```c(.*?)```"
        return re.findall(pattern1, text, re.DOTALL | re.MULTILINE)

    for i in range(len(matches2)):
        inPattern = r"```c(.*?{.*?}.*?)```"
        inMatches = re.findall(inPattern, matches2[i], re.DOTALL | re.MULTILINE)
        if inMatches:
            matches2[i] = inMatches[0]
        else:
            matches2[i] = matches2[i].split(')', 1)[0] + ');\n\n'
    return matches2


def current_name_busy(name):
    return os.path.exists(name)


result_file = "./apps/data/data.jsonl"
file_path = result_file.rsplit('.', 1)[0] + ".c"

json_objects = []
with open(result_file, 'r') as file:
    for line in file:
        json_object = json.loads(line)
        json_objects.append(json_object)

i = 0
c_file_path = file_path
while(current_name_busy(c_file_path)):
    i += 1
    c_file_path = f'{i}.'.join(file_path.rsplit('.', 1))
print(c_file_path)


with open(c_file_path, 'w') as file:
    include1 = '#include <specfunc.h>'
    include2 = '#include "specfunc.h"'
    # file.write(include)
    for obj in json_objects[1:]:
        tmp_strings = obj['result'].replace(include1, "").replace(include2, "").replace("\\", "")
        strings = extract_substrings(tmp_strings)

        file.writelines([string.replace("\nc\n", "") for string in strings] if strings else "")
