from hugchat import hugchat
from hugchat.login import Login
from dotenv import dotenv_values
import time
import sys
import os


def generate_response(prompt_input, email, passwd, sys_prompt=""):
    # Hugging Face Login
    start_time = time.time()

    sign = Login(email, passwd)
    cookies = sign.login()
    # Create ChatBot
    chatbot = hugchat.ChatBot(cookies=cookies.get_dict(), default_llm=1,
                              system_prompt=sys_prompt)
    output = chatbot.query(prompt_input, max_new_tokens=4096)
    print(output)

    end_time = time.time()
    print('TIME SPENT: %.1f s.' % (end_time - start_time))
    print('----------\n')


def run(dir_path=None, sys_prompt_flag=False):
    secrets = dotenv_values("hf.env")
    hf_email = secrets['EMAIL']
    hf_pass = secrets['PASS']

    sys_prompt = ""
    if sys_prompt_flag:
        sys_prompt = input("Enter sys_prompt:\n")

    if dir_path:
        directory = os.fsencode(dir_path)

        print('Started Dir Handling\n')
        for file in os.listdir(directory):
            filename = dir_path + ('' if dir_path.endswith('/') else '/') + os.fsdecode(file)
            with open(filename) as fd:
                prompt = '\n'.join([line.rstrip() for line in fd])
                generate_response(prompt, hf_email, hf_pass, sys_prompt)
        print('Stopped Dir Handling\n')
        return

    while True:
        prompt = input("Enter Prompt\n")
        if prompt == '--':
            return
        generate_response(prompt, hf_email, hf_pass, sys_prompt)


if __name__ == '__main__':
    dir_path = None
    sys_prompt = False

    if len(sys.argv) > 1:
        argv = sys.argv

        if 'h' in argv:
            print('LLM: LLama-70b. AVG Time: 30 s.\n'
                  'Аргументы запуска:\n'
                  'h - help\n'
                  'pwd - Path to Prompts dir\n'
                  's - Enable System Prompt\n\n'
                  'Положите в текущую папку файл hf.env, в котором '
                  'хранятся логин и пароль от HuggingFace в формате:\n'
                  'EMAIL=...\n'
                  'PASS=...\n\n'
                  'Вы можете задать путь к папке, в которой хранятся промпты.\n'
                  'Для этого запишите путь к папке в командной строке.\n\n'
                  'Каждый output отделен строкой из 10 "-":\n'
                  '----------\n\n'
                  'Либо вводить Промпты напрямую, чтобы завершить напишите --')
            exit(0)
        if 's' in argv:
            sys_prompt = True
            argv.remove('s')
        dir_path = sys.argv[1]
    run(dir_path, sys_prompt)
