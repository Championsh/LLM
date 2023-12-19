# ML and LLM for Code Analysis

This repository is devoted to using Large Language Models for solving Code Analysis tasks.
- 🔗 Useful Links:
    - [Comparison Table](https://docs.google.com/spreadsheets/d/1rRWf4m6lHOHYkGDgsgGHDp5UGOyMlsOScjhD4Lz34zE/edit?usp=sharing)

## Project Tasks:
1. **Warnings Explanation**:
    - **Svace warnings** explanations, i.e. more simple / detailed / exemplified warning text.
    - **Criteria**:
        - ***Output Logic*** (*poor* / *medium* / *good*) - the ability of the current LLM to give a logical output, i.e. if the output is well-correlated with the code;
        - ***Response Time*** (*slow* / *normal* / *fast*) - the ability of the current LLM to generate an output in a decent amount of time;
        - ***Answer Simplicity*** (*poor* / *medium* / *good*) - the ability of the current LLM to give a simle output, i.e. if the given explanation can be understood easily.
        - ***Answer Detalisation*** (*poor* / *medium* / *good*) - the ability of the current LLM to give a detailed output, i.e. if every part of the explanation is justified;
        - ***Output Logic*** (*poor* / *medium* / *good*) - the ability of the current LLM to give a logical output
        - ***Output Logic*** (*poor* / *medium* / *good*) - the ability of the current LLM to give a logical output

## Tested LLM Models:
- Models selected based on test results:
    - [DeepSeek Coder 33B](https://chat.deepseek.com/),
    - [ChatGPT-3.5B](https://chat.openai.com/),
    - [Falcon-180B](https://huggingface.co/spaces/tiiuae/falcon-180b-demo),
    - [Mistral 8x7B](https://docs.mistral.ai/),
    - [Qwen-14B](https://huggingface.co/spaces/artificialguybr/qwen-14b-chat-demo),
    - [Llama 2](https://www.llama2.ai/)
- Models discarded based on test results:
    - ORCA_LLaMA_70B_QLoRA,
    - FashionGPT-70B-V1.1,
    - AutoGen (GPT based),
    - Marcoroni-70B-v1,
    - Uni-TianYan,
    - Falcon-40B,
    - Llama2-13B,
    - Llama2-70B,
    - YandexGPT,
    - Starchat,
    - Gigachat,
    - TheB.Ai

## Project Tree
```
├── 1_warning_explanation
│   └── ...
├── 2_test_translation
│   ├── prompt_1
│   │   └── ...
│   ├── prompt_2
│   │   └── ...
│   ├── prompt_3
│   │   └── ...
│   ├── prompt_4
│   │   └── ...
│   ├── prompt_5
│   │   └── ...
│   └── prompts
│       └── ...
├── 3_test_generation
│   └── tg_1_prompt.txt
├── 4_spec_generation
│   └── ...
├── 5_comment_generation
│   └── ...
├── apps
│   ├── hf_not_working.py
│   ├── llama_chat.py
│   ├── prompts
│   │   ├── sg_9_prompt.txt
│   │   ├── we-1-prompt.txt
│   │   └── we-3-prompt.txt
│   ├── requirements.txt
│   └── unused
│       └── ...
├── .gitignore
├── ReadMe
├── sg_rules
├── src
│   └── inference.py
└── test_generation_NotATask
    └── ...
```
