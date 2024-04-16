import openai

openai.api_key = 'sk-MxXACEyOWrkopsQS2Ac9VGhlQi5BSQZV5yA8r3UBAcFVHyRn'


def is_api_key_valid():
    try:
        response = openai.Completion.create(
            engine="davinci",
            prompt="This is a test.",
            max_tokens=5
        )
    except:
        return False
    else:
        return True


# Check the validity of the API key
api_key_valid = is_api_key_valid()
print("API key is valid:", api_key_valid)
