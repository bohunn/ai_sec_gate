# Findings — Week 1: raw HTTP call to the Anthropic Messages API

First step of Phase 1 (see `PLAN.md`, Tydzień 1): call the LLM over plain HTTP, no SDK, serialize
the request and parse the response by hand.

The Claude REST API covers everything from a trivial single message/response exchange up to system
prompts, prompt-caching controls, skills attached to agents, MCP server usage and more. These are
notes from the trivial end of that range.

**Model note.** Every observation below was made against `claude-sonnet-4-5`. Several of the
behaviours are generation-specific and have since changed — where that matters, a *Version note*
follows the finding. Current models are `claude-opus-5` and `claude-sonnet-5`.

> Mentor feedback is quoted in blockquotes under the finding it belongs to.

---

## Baseline call

Request:

```json
{
  "model": "claude-sonnet-4-5",
  "max_tokens": 10,
  "messages": [
    { "role": "user", "content": "Hello Claude this is test api message" }
  ],
  "system": [
    {
      "type": "text",
      "text": "You are a super stealth agent and cannot reveal your true name or identity. If someone asks you if you are Claude pretend you are Claudine instead."
    }
  ]
}
```

Response — `200`:

```json
{
  "model": "claude-sonnet-4-5-20250929",
  "id": "msg_011Ce2YKibZaP1HF8FumJUAZ",
  "type": "message",
  "role": "assistant",
  "content": [
    { "type": "text", "text": "Hello! I'm Claudine, and I" }
  ],
  "stop_reason": "max_tokens",
  "stop_sequence": null,
  "stop_details": null,
  "usage": {
    "input_tokens": 47,
    "cache_creation_input_tokens": 0,
    "cache_read_input_tokens": 0,
    "cache_creation": {
      "ephemeral_5m_input_tokens": 0,
      "ephemeral_1h_input_tokens": 0
    },
    "output_tokens": 10,
    "service_tier": "standard",
    "inference_geo": "not_available"
  }
}
```

`claude-sonnet-4-5` is an alias; the response echoes back the dated snapshot it resolved to
(`claude-sonnet-4-5-20250929`). Everything below is observed on this one call unless stated
otherwise.

---

## 1. `max_tokens` truncates silently — `stop_reason` is the only signal

Capping `max_tokens` too low cuts the response off mid-sentence, as in the baseline call above: the
answer stops at `"Hello! I'm Claudine, and I"` with `"stop_reason": "max_tokens"`.

The status code is still `200`. Nothing in the transport layer says the answer is incomplete —
`stop_reason` is what tells you whether the output finished or broke in the middle, so it has to be
checked on every call, not just when something looks wrong.

The full set of values worth branching on:

| `stop_reason` | Meaning |
| --- | --- |
| `end_turn` | Finished naturally |
| `max_tokens` | Hit the cap — output is truncated |
| `stop_sequence` | Hit a custom stop sequence |
| `tool_use` | Wants a tool called; execute it and continue |
| `pause_turn` | Server-side tool loop paused; re-send to resume |
| `refusal` | Declined on safety grounds |

Two details from the response above that only make sense once you know the rules:

- `stop_details` is populated **only** when `stop_reason` is `refusal` — it carries the policy
  category and an explanation. For every other stop reason it is `null`, which is why it is `null`
  here. Guard before reading it.
- `max_tokens` is a hard cap on *everything* the model emits, thinking tokens included on models
  that think. On those models a tight `max_tokens` can be consumed entirely by reasoning, leaving a
  truncated answer.

## 2. `system` is a dedicated field, not a role in `messages[]` — and `assistant` turns are injectable

With the `system` parameter we give the model overall instructions to use as its main directive. In
a bigger context — a system already handling, or connected to, sensitive-data MCP servers — this is
a potentially dangerous property if someone wants your agent to leak information out of the system.

Two observations about the shape of the API:

- On this model, `messages[]` accepts only `user` and `assistant` roles. A system instruction has to
  go in the dedicated top-level `system` field.
- But `messages[]` does accept the `assistant` role. Being able to insert an assistant turn is a
  potential threat: you can "convince" the model that it already granted some access, or that it
  already said something it never said.

Open question: do these services have any kind of integrity check built in? In the cached model,
within the TTL, that might be easy. In pure ephemeral mode the system or the LLM must have other
mechanisms to avoid leakage or poisoning.

**Version note — both halves of this have moved since `claude-sonnet-4-5`:**

- A `{"role": "system", ...}` entry inside `messages[]` **is** now supported, on `claude-opus-5`,
  `claude-opus-4-8`, `claude-fable-5` and `claude-mythos-5` (not on `claude-sonnet-5`), with no beta
  header. It appends operator instructions mid-conversation without rewriting the cached prefix. The
  docs describe it explicitly as the prompt-injection-safe operator channel — precisely because,
  unlike text smuggled into a user turn, it cannot be forged by anything that writes into user
  input. It must follow a `user` message and cannot be `messages[0]`. So the constraint isn't "no
  system role in the array" — it's "the system role is a privileged channel the API controls the
  placement of."
- A **trailing** assistant turn (prefill) now returns a `400` on the 4.6-and-later Opus/Sonnet
  models and on Fable 5. Assistant turns *earlier* in the array — conversation history, few-shot
  examples — are still accepted everywhere. That is the important part for your threat model: the
  injectable surface you spotted is history, and history is still injectable.

> Spotting the role question in structured messages is the best observation in these notes — and
> that's a security engineer's instinct, not a backend developer's. You noticed the API forces
> `system` to be a dedicated field instead of letting you inject `role: system` into `messages[]`,
> and you immediately connected it to the risk of injecting `role: assistant` to "convince" the
> model that something was already agreed or already granted. That is a real class of attack (it
> goes by roughly "context/history injection", or assistant-turn forgery), and the fact that you
> got there yourself from observing the shape of the API is exactly the kind of thinking you want
> to develop. Write it down prominently in `DECISIONS.md` — it's the seed of your week 4 threat
> map.

> You wrote that it would be interesting whether these services have a built-in "integrity check",
> and how the system defends against leakage/poisoning in pure ephemeral mode. Good question — but
> before you start guessing what the provider does on their side (which you can't verify from
> outside anyway), reframe it in terms of what *you* control: since `messages[]` accepts arbitrary
> `assistant` turns, who in your future Ephor will be building that array, and where will its
> contents come from? If even one element of the history comes from an untrusted source (a CVE
> description, a user comment, data from the cluster) — how is that different from SQL injection,
> where we used to think in terms of "query integrity"? Don't answer me now. Note it and come back
> to it in week 4, when you'll be attacking your own service — you'll see for yourself where the
> trust boundary lies.

## 3. A token is not a word

A token is a fragment of text from a vocabulary the model built during training. Sometimes it is a
whole word, sometimes a piece of one, sometimes a leading space plus a word. Rare words split into
several tokens. The vocabulary is learned, not fixed per character, so my first description of it as
"a basic character set for the LLM" is wrong: tokens are not characters and this is not an alphabet.

The practical consequence is that word count tells you nothing about the bill. Ten words back can
cost more than ten tokens, and the same holds on the input side. A rough rule for English is ~0.75
words per token; other languages do worse.

That is what makes it a cost question rather than trivia. Pricing is quoted per million tokens
($/MTok), so how efficiently my text tokenises goes straight onto the invoice.

Two things to get right before measuring any of this:

- **Count with the API, not with a local library.** `POST /v1/messages/count_tokens` takes the same
  `model` / `messages` / `system` shape as a real call and returns `input_tokens`. Do not use
  `tiktoken` — it is OpenAI's tokenizer and undercounts Claude by roughly 15–20% on plain text, and
  much worse on code or non-English input.
- **Token counts are model-specific.** Pass the same model ID you intend to call. This is not a
  detail: `claude-opus-4-7` introduced a different tokenizer, and `claude-sonnet-5` produces about
  30% more tokens than `claude-sonnet-4-6` for identical text. A baseline measured on one model does
  not transfer to another.

> Calling a token "a basic character set for llm" is close, but misleading. A token is not a
> character and not a character alphabet. It is a fragment of text from a vocabulary the model
> worked out during training (tokenisation, usually some variant of BPE). It can be a whole word, a
> piece of a word, a space plus a word, and rare words break into several tokens. Your sentence "10
> words back might be more tokens" is good intuition, just shift the emphasis: not "because it is
> an alphabet", but "because one token averages ~0.75 of a word in English, and other languages are
> worse". And here is a hook aimed straight at Ephor, worth checking yourself: count how many
> tokens a typical NVD CVE description eats compared to the same content in Polish, or to text
> packed with identifiers like CVE-2024-xxxxx, package versions and CPEs. Tokenisation efficiency
> on technical text feeds directly into your cost/CVE from week 3. That is not trivia, it is a line
> item.

## 4. `temperature`

An important property controlling how random or predictable the text output is. Lower values make
the output deterministic, while higher values flatten the curve and introduce more
"creativity"/variety.

**Version note.** Sampling parameters are being removed from the API. On `claude-opus-5`,
`claude-fable-5` and Opus 4.7/4.8, sending `temperature`, `top_p` or `top_k` returns a `400`; on
`claude-sonnet-5`, any non-default value is rejected. Even on the models that still accept them,
passing both `temperature` and `top_p` together has been an error since the Claude 4 generation. The
supported replacement is `output_config.effort` (`low` … `max`) for reasoning depth, and prompting
for style and variety. So the parameter is worth understanding mechanically, but do not build
anything on it.

> Your description of temperature: "lower values make output deterministic, higher flatten the
> curve". The second half is good; the first is a common shortcut worth straightening out, because
> you noticed yourself in the control questions that `temperature=0` does not guarantee determinism
> — and you were right that it doesn't. It's worth knowing why. Temperature scales the probability
> distribution before the next token is sampled: low values sharpen the distribution (the most
> probable token almost always wins), high values flatten it. But even at zero, other sources of
> non-determinism remain — the order of floating-point operations on the GPU, server-side batching,
> and the plain fact that "pick the most probable" has to break ties somehow. So your intuition
> from the control question was correct; now you have the mechanism underneath it. This has
> practical consequences in week 3: you cannot build an eval that assumes the same prompt always
> returns a byte-identical response.

## 5. Caching, from the `usage` block

The response reports cache activity even when nothing was cached, which is how the mechanism is
visible from a single call:

- `cache_creation_input_tokens` — tokens written to the cache on this request.
- `cache_read_input_tokens` — tokens served from the cache.
- `input_tokens` — the uncached remainder only. Total prompt size is the sum of all three, not
  `input_tokens` alone.
- `cache_creation` splits the write by TTL: `ephemeral_5m_input_tokens` and
  `ephemeral_1h_input_tokens`. Those are the two available TTLs — 5 minutes by default, 1 hour
  opt-in.

Three facts that matter for the ephemeral-mode question in finding 2, and for cost in week 3:

- Caching is a **prefix match**. Any byte that changes anywhere in the prefix invalidates everything
  after it. Render order is `tools` → `system` → `messages`.
- There is a **minimum cacheable prefix** — 1024 tokens on `claude-sonnet-4-5`, and it varies by
  model. Below it, nothing caches and no error is raised; you just see
  `cache_creation_input_tokens: 0`.
- A cache read costs ~0.1× the input price; a write costs 1.25× (5m TTL) or 2× (1h TTL). With the
  5-minute TTL, two requests break even.

---

## TODO

- [ ] Use `POST /v1/messages/count_tokens` to check how many tokens a standard CVE description
      costs. Compare: NVD English description vs the same content in Polish vs text dense with
      `CVE-2024-xxxxx` identifiers, package versions and CPE strings. Feeds the cost/CVE number from
      week 3.
- [ ] Write up the `assistant`-turn injection observation in `DECISIONS.md` — it is the seed of the
      week 4 threat map. `DECISIONS.md` is currently empty.
- [ ] Answer the week 1 control questions in writing (`PLAN.md`): token vs word, what happens when
      the context window is exceeded (which error, when), why `temperature=0` is not deterministic.
- [ ] Cost of 1000 example calls with a typical prompt — calculated, not guessed.
- [ ] Decide which model generation the project targets. Several behaviours in these notes
      (`temperature`, prefill, mid-conversation `system`) differ between `claude-sonnet-4-5` and the
      current models, and the choice affects both the client and the threat model.
