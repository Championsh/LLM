from os import path

pwd = "C:\\Users\\Андрей\\Documents\\LLM\\we\\"


def current_name_busy(name):
    return path.exists


def get_pwd(counter):
    return pwd + str(counter) + '.txt'


def gen_prompt_id():
    while True:
        counter = 1
        cur_prompt_path = get_pwd(counter)
        while current_name_busy(cur_prompt_path):
            counter += 1
            cur_prompt_path = get_pwd(counter)
        yield cur_prompt_path


prompt_id = gen_prompt_id()

if __name__ == '__main__':
    print(1 == next(prompt_id))
