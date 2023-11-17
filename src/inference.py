import json
import os
import shutil
import requests

#import gradio as gr
from huggingface_hub import Repository, InferenceClient

HF_TOKEN = os.environ.get("HF_TOKEN", "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")
API_URL = "https://api-inference.huggingface.co/models/tiiuae/falcon-40b-instruct"

STOP_SEQUENCES = ["\nUser:", "<|endoftext|>", " User:", "###"]

client = InferenceClient(
    API_URL,
    headers={"Authorization": f"Bearer {HF_TOKEN}"},
)

def format_prompt(message, history, system_prompt):
    prompt = ""
    if system_prompt:
        prompt += f"System: {system_prompt}\n"
    for user_prompt, bot_response in history:
        prompt += f"User: {user_prompt}\n"
        prompt += f"Falcon: {bot_response}\n" # Response already contains "Falcon: "
    prompt += f"""User: {message}
    Falcon:"""
    print(prompt)
    return prompt

seed = 42

def generate(
    prompt, history, system_prompt="", temperature=0.9, max_new_tokens=256, top_p=0.95, repetition_penalty=1.0,
):
    temperature = float(temperature)
    if temperature < 1e-2:
        temperature = 1e-2
    top_p = float(top_p)
    global seed
    generate_kwargs = dict(
        temperature=temperature,
        max_new_tokens=max_new_tokens,
        top_p=top_p,
        repetition_penalty=repetition_penalty,
        stop_sequences=STOP_SEQUENCES,
        do_sample=True,
        seed=seed,
    )
    seed = seed + 1
    formatted_prompt = format_prompt(prompt, history, system_prompt)
    
    try:
        stream = client.text_generation(formatted_prompt, **generate_kwargs, stream=True, details=True, return_full_text=False)
        output = ""
        
        for response in stream:
            output += response.token.text
            print(output)
            for stop_str in STOP_SEQUENCES:
                if output.endswith(stop_str):
                    output = output[:-len(stop_str)]
                    output = output.rstrip()
                    yield output
            yield output
    except Exception as e:
        print(f"Error while generating: {e}")
    return output


print(list(generate("Hello", "")))