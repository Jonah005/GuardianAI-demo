# Model Configuration

GuardianAI sends chat-completions requests to an OpenAI-compatible endpoint. The model can run on another machine, for example on Colab or Kaggle behind a vLLM server, while Langflow stays local.

The request URL is `GUARDIAN_MODEL_BASE_URL` followed by `GUARDIAN_MODEL_CHAT_PATH`.

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `GUARDIAN_MODEL_BASE_URL` | none (required) | Base URL, e.g. `http://your-model-host:8000/v1` |
| `GUARDIAN_MODEL_NAME` | none (required) | Model name sent in each request |
| `GUARDIAN_MODEL_CHAT_PATH` | `/chat/completions` | Path appended to the base URL |
| `GUARDIAN_MODEL_API_KEY` | empty | Sent as `Authorization: Bearer <key>` when set |
| `GUARDIAN_MODEL_PROVIDER` | `local` | `local` for the fine-tuned model; anything else is treated as a hosted API (see below) |
| `GUARDIAN_MODEL_JSON_MODE` | `false` | Adds `response_format: {"type": "json_object"}` to requests |
| `GUARDIAN_MODEL_TIMEOUT_SECONDS` | `240` | HTTP timeout |
| `GUARDIAN_MODEL_MAX_TOKENS` | `2500` | Maximum tokens per response |
| `GUARDIAN_MODEL_TEMPERATURE` | `0.7` | Sampling temperature (see provider notes) |

Placeholder example:

```env
GUARDIAN_MODEL_BASE_URL=http://your-model-host:8000/v1
GUARDIAN_MODEL_CHAT_PATH=/chat/completions
GUARDIAN_MODEL_NAME=your-model-name
GUARDIAN_MODEL_API_KEY=your-model-api-key
```

If the model runs on another machine over [Tailscale](https://tailscale.com/), use the machine's Tailscale IP or MagicDNS name as the host, for example `http://your-host.your-tailnet.ts.net:8000/v1`.

## Providers

**`local` (default)** is the fine-tuned Guardian model served with vLLM. Requests include `chat_template_kwargs: {"enable_thinking": false}`, and the sampling temperature is never lower than `0.9`, even if `GUARDIAN_MODEL_TEMPERATURE` is set lower.

**Any other value** (for example `deepseek`) is treated as a generic hosted OpenAI-compatible API. The vLLM-only field is omitted and `GUARDIAN_MODEL_TEMPERATURE` is used as set (`0.7` if it is `0`). The dashboard's model picker sets the provider, API key, base URL and model name for a run.

## JSON Mode

```env
GUARDIAN_MODEL_JSON_MODE=true
```

Enable this only if your server supports `response_format`. Leave it `false` otherwise. GuardianAI validates every structured response against its schema, and re-asks the model up to three times if the reply is not valid.

## Request Format

```json
{
  "model": "your-model-name",
  "messages": [{"role": "user", "content": "..."}],
  "temperature": 0.9,
  "top_p": 0.95,
  "max_tokens": 2500,
  "stream": false,
  "chat_template_kwargs": {"enable_thinking": false}
}
```

`temperature` is the effective value after the provider rules above. `chat_template_kwargs` is only sent for the `local` provider. Failed requests are retried up to three times with backoff.

## Accepted Response Shapes

The generated text is read from the first of these that is present:

```json
{"choices": [{"message": {"content": "..."}}]}
```

```json
{"choices": [{"text": "..."}]}
```

```json
{"content": "..."}
```

The top-level keys `text`, `response`, `generated_text`, `output_text` and `output` are also accepted.
