rf_path = "./libs/%s"
wf_path = "./res_%s"
keywords = ["ENGINE", "X500", "SSL", "OPENSSL"]

# if not any(keyword in "BIO_ssl_shutdown" for keyword in keywords):
#     print("NO!")

filename = str(input())
with open(rf_path % filename, "r") as read_file:
    with open(wf_path % filename, "w") as write_file:
        for line in read_file:
            line = line.replace('•','').split('\t')[0]
            # if not any(keyword in line for keyword in keywords):
            #     continue
            write_file.write(line.strip()+'\n')
