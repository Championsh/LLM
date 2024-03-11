rf_path = "./%s"
wf_path = "./res_%s"

filename = str(input())
with open(rf_path % filename, "r") as read_file:
    with open(wf_path % filename, "w") as write_file:
        for line in read_file:
            if "free" in line:
                continue
            line = line.replace('•','')
            write_file.write(line.split('\t')[0]+'\n')
