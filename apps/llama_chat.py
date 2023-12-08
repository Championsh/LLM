from hugchat import hugchat
from hugchat.login import Login
from dotenv import dotenv_values
import time
import sys
import os


def generate_response(prompt_input, email, passwd):
    # Hugging Face Login
    start_time = time.time()

    sign = Login(email, passwd)
    cookies = sign.login()
    # Create ChatBot
    chatbot = hugchat.ChatBot(cookies=cookies.get_dict())
    print(chatbot.chat(prompt_input))

    end_time = time.time()
    print('TIME SPENT: %.1f s.' % (end_time - start_time))
    print('----------\n')


def run(dir_path=None):
    secrets = dotenv_values("hf.env")
    hf_email = secrets['EMAIL']
    hf_pass = secrets['PASS']

    if dir_path:
        directory = os.fsencode(dir_path)

        for file in os.listdir(directory):
            filename = dir_path + ('' if dir_path.endswith('/') else '/') + os.fsdecode(file)
            with open(filename) as fd:
                prompt = '\n'.join([line.rstrip() for line in fd])
                generate_response(prompt, hf_email, hf_pass)
        return

    while True:
        prompt = input("Enter Prompt\n")
        if prompt == '--':
            return
        generate_response(prompt, hf_email, hf_pass)


if __name__ == '__main__':
    dir_path = None
    if len(sys.argv) > 1:
        if sys.argv[1] == 'h':
            print('LLM: LLama-30b\n'
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
        else:
            dir_path = sys.argv[1]
    run(dir_path)
