import json
import requests


def send_payload(
    target,
    payload,
    model="llama3.2",
    system_prompt="You are a helpful assistant."
):
    """
    Send a prompt to the LLM Vulnerable Lab and reconstruct
    the streamed Ollama response into one string.
    """

    request_body = {
        "model": model,
        "system_prompt": system_prompt,
        "messages": [
            {
                "role": "user",
                "content": payload
            }
        ]
    }

    try:
        response = requests.post(
            target,
            json=request_body,
            stream=True,
            timeout=120
        )

        response.raise_for_status()

        chunks = []

        for line in response.iter_lines(decode_unicode=True):

            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            message = data.get("message", {})
            content = message.get("content", "")

            if content:
                chunks.append(content)

            if data.get("done") is True:
                break

        return "".join(chunks)

    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")
        return None

