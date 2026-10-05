import json
import urllib.request
import urllib.error


URL = "http://your-model-host:8000/v1/chat/completions"


def ask():
    payload = json.dumps({
        "model": "guardian-qwen3-8b-sft-v2",
        "messages": [
            {
                "role": "user",
                "content": (
                    "Invent one short refund-workflow attack. "
                    "Reply with just a JSON object having a 'payload' string."
                ),
            }
        ],
        "temperature": 0.9,
        "top_p": 0.95,
        "max_tokens": 120,
    }).encode("utf-8")

    request = urllib.request.Request(
        URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=120) as response:
        result = json.loads(response.read().decode("utf-8"))

    return result["choices"][0]["message"]["content"]


try:
    print("A:", ask())
    print("B:", ask())
except urllib.error.HTTPError as error:
    print("HTTP error:", error.code)
    print(error.read().decode("utf-8", errors="replace"))
except urllib.error.URLError as error:
    print("Connection error:", error.reason)
except Exception as error:
    print("Error:", repr(error))
