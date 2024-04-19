from transformers import AutoTokenizer, AutoModelForSeq2SeqLM


model_name = "deepseek-ai/deepseek-llm-67b-chat"

model = AutoModelForSeq2SeqLM.from_pretrained(model_name)
tokenizer = AutoTokenizer.from_pretrained(model_name)

conversation_history = []

while True:
    history_string = '\n'.join(conversation_history)

    input_text = 'Hello!'
    inputs = tokenizer.encode_plus(history_string, input_text, return_tensors="pt")

    outputs = model.generate(**inputs)
    response = tokenizer.decode(outputs[0], skip_special_tokens=True).strip()

    conversation_history.append(input_text)
    conversation_history.append(response)
