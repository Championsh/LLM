# Clean messy prototype files

# Mess ones are located at:
rf_path = "./init-libs/protos/messy/%s"

# Clean ones are located at:
wf_path = "./init-libs/protos/res_%s"

# Filter-keywords for resulting prototypes
keywords = ["ENGINE", "X500", "SSL", "OPENSSL"]

filename = str(input())
with open(rf_path % filename, "r") as read_file:
    with open(wf_path % filename, "w") as write_file:
        for line in read_file:
            line = line.replace('•','').split('\t')[0]
            # if not any(keyword in line for keyword in keywords):
            #     continue
            write_file.write(line.strip()+'\n')
