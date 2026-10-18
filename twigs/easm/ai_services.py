"""Self-hosted / shadow AI inference infrastructure detection: LLM serving
frameworks (Ollama, Hugging Face TGI, vLLM/LocalAI/LM Studio and other
OpenAI-API-compatible backends, text-generation-webui, Triton, TensorFlow
Serving), chat front-ends (Open WebUI), low-code LLM/agent app builders
(Flowise, Langflow), the LiteLLM gateway orgs self-host to centralize/govern
LLM access, the MLflow model-registry/experiment-tracking server, and the
vector databases commonly paired with all of the above for RAG (ChromaDB,
Qdrant, Weaviate, Milvus) - left reachable from the internet, usually with no
authentication by default.

This is the EASM-visible subset of shadow AI: unlike twigs/shadow_ai.py (host
mode, credentialed) this runs unauthenticated from the outside and can only
see what is actually exposed, not what is merely installed. Each signature is
matched on a distinctive, product-specific response (JSON body shape, header,
or error-message wording tied to the real default/common port) - not just
"port open" or "200 OK" - for the same false-positive-avoidance reasons laid
out in exposed_panels.py (these ports are commonly reused by unrelated web
apps, e.g. 8080/3000/8000)."""
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from .constants import RATING_MEDIUM, RATING_HIGH, RATING_INFO, ISSUE_TYPE_SHADOW_AI, PROBE_TIMEOUT_SHORT
from .util import _new_issue, _http_get
from .exposed_panels import _panel_signature_matches

PROBE_WORKERS = 32

# Each entry: 'name', 'ports' (tried in order, first match wins), 'paths'
# (tried per port), plus the same signature fields exposed_panels.py uses
# (header_contains / body_prefix / body_contains_any / body_contains_all /
# not_html). 'rating' reflects what an unauthenticated caller can actually do
# once this is confirmed reachable: full inference/data access (HIGH) vs. a
# front-end that may still gate behind its own login, or presence-only
# disclosure (MEDIUM).
AI_SERVICE_CHECKS = [
    {
        'name': 'Ollama', 'ports': [11434], 'paths': ['/'],
        'body_contains_any': ['Ollama is running'], 'rating': RATING_HIGH,
        'description': "An Ollama local-LLM server appears to be exposed to the internet. Ollama binds to localhost by default; this instance has been reconfigured (e.g. OLLAMA_HOST=0.0.0.0) to listen on all interfaces. Its API has no authentication by default, allowing anyone to list, pull, and run inference against every model it hosts - unmetered compute abuse, and potential exposure of proprietary fine-tuned/custom models.",
        'remediation': "Restrict access to Ollama's port (11434) to a VPN/trusted network or put it behind an authenticating reverse proxy. Do not set OLLAMA_HOST=0.0.0.0 on internet-facing hosts.",
    },
    {
        'name': 'Hugging Face Text Generation Inference (TGI)', 'ports': [8080, 3000, 8000, 80], 'paths': ['/info'],
        'body_contains_all': ['"model_id"', '"max_concurrent_requests"'], 'not_html': True, 'rating': RATING_HIGH,
        'description': "A Hugging Face Text Generation Inference (TGI) server appears to be exposed to the internet, identified via its /info endpoint. TGI has no authentication by default, allowing anyone to enumerate the loaded model and submit arbitrary prompts - unmetered compute abuse, and potential exposure of a proprietary fine-tuned model.",
        'remediation': "Restrict access to TGI to a VPN/trusted network or place it behind an authenticating API gateway.",
    },
    {
        'name': 'Self-hosted OpenAI-API-compatible LLM inference server',
        'ports': [8000, 8001, 5000, 1234, 7861, 8080], 'paths': ['/v1/models'],
        'body_contains_all': ['"owned_by"'], 'body_contains_any': ['"object": "list"', '"object":"list"'],
        'not_html': True, 'rating': RATING_HIGH,
        'description': "A self-hosted LLM inference server exposing an OpenAI-compatible API (e.g. vLLM, text-generation-inference, llama.cpp server, LocalAI, LM Studio, or similar) appears to be reachable from the internet, identified via its /v1/models endpoint response shape. Such servers typically require no authentication by default, allowing anyone to enumerate hosted/fine-tuned models and submit arbitrary prompts - unmetered compute abuse, and potential exposure of proprietary models or any data embedded in system prompts/RAG context.",
        'remediation': "Restrict access to this inference API to a VPN/trusted network or place it behind an authenticating API gateway (API key, OAuth) - never expose an OpenAI-compatible completion endpoint directly to the internet without one.",
    },
    {
        'name': 'Open WebUI', 'ports': [8080, 3000], 'paths': ['/'],
        'body_contains_any': ['<title>Open WebUI</title>', 'content="Open WebUI"'], 'rating': RATING_MEDIUM,
        'description': "An Open WebUI instance (a self-hosted ChatGPT-style front-end, commonly paired with Ollama or other local LLM backends) appears to be exposed to the internet. This is informational unless its own authentication is also disabled (e.g. WEBUI_AUTH=False or open self-signup) - confirm separately - but it confirms unmanaged/shadow AI chat infrastructure is internet-facing.",
        'remediation': "Confirm this instance is intended to be internet-facing. If so, ensure its own authentication is enabled and public self-signup is disabled; otherwise restrict access to a VPN/trusted network.",
    },
    {
        'name': 'text-generation-webui', 'ports': [7860], 'paths': ['/'],
        'body_contains_any': ['Text generation web UI', 'text-generation-webui'], 'rating': RATING_HIGH,
        'description': "A text-generation-webui (oobabooga) instance appears to be exposed to the internet. This Gradio-based UI has no authentication by default and provides full chat/completion access to whatever model it has loaded, plus (depending on configuration) extensions that can execute code or read/write files on the host.",
        'remediation': "Restrict access to a VPN/trusted network, or launch with --gradio-auth to require a username/password. Never expose the default unauthenticated instance to the internet.",
    },
    {
        'name': 'LiteLLM gateway', 'ports': [4000], 'paths': ['/metrics'],
        'body_contains_any': ['litellm_requests_metric', 'litellm_total_tokens', 'litellm_llm_api_latency_metric'],
        'rating': RATING_HIGH,
        'description': "A LiteLLM proxy instance appears to be exposed to the internet, identified via its Prometheus metrics endpoint. LiteLLM is commonly self-hosted specifically to centralize/govern an organization's LLM provider access (OpenAI, Anthropic, etc.) behind one gateway; an unauthenticated instance ironically defeats that purpose, potentially allowing anyone to route requests through the org's configured provider keys.",
        'remediation': "Restrict access to the LiteLLM proxy to a VPN/trusted network, and require its virtual-key authentication (master key / per-user keys) for all proxied requests, not just the admin UI.",
    },
    {
        'name': 'Flowise', 'ports': [3000], 'paths': ['/'],
        'body_contains_any': ['<title>Flowise</title>', 'content="Flowise'], 'rating': RATING_HIGH,
        'description': "A Flowise (low-code LLM/agent workflow builder) instance appears to be exposed to the internet. Flowise has no authentication enabled by default; an exposed instance allows anyone to view/modify workflows and can expose the organization's configured LLM/API provider credentials stored within them.",
        'remediation': "Restrict access to Flowise to a VPN/trusted network, or set FLOWISE_USERNAME/FLOWISE_PASSWORD (basic auth) before exposing it beyond localhost.",
    },
    {
        'name': 'Langflow', 'ports': [7860, 7868], 'paths': ['/'],
        'body_contains_any': ['<title>Langflow</title>', 'content="Langflow'], 'rating': RATING_HIGH,
        'description': "A Langflow (low-code LLM/agent workflow builder) instance appears to be exposed to the internet. Like Flowise, Langflow has no authentication enabled by default; an exposed instance allows anyone to view/modify flows and can expose the organization's configured LLM/API provider credentials stored within them.",
        'remediation': "Restrict access to Langflow to a VPN/trusted network, or enable its LANGFLOW_AUTO_LOGIN=false + superuser authentication before exposing it beyond localhost.",
    },
    {
        'name': 'MLflow', 'ports': [5000], 'paths': ['/'],
        'body_contains_any': ['<title>MLflow</title>'], 'rating': RATING_HIGH,
        'description': "An MLflow tracking server / model registry instance appears to be exposed to the internet. MLflow has no authentication by default, allowing anyone to browse experiments, download model artifacts, and access the model registry - frequently proprietary fine-tuned models and training data/metrics.",
        'remediation': "Restrict access to MLflow to a VPN/trusted network, or place it behind an authenticating reverse proxy (MLflow itself has no built-in auth in open-source releases).",
    },
    {
        'name': 'Triton Inference Server', 'ports': [8000, 8001], 'paths': ['/v2'],
        'body_contains_any': ['"name":"triton"', '"name": "triton"'], 'not_html': True, 'rating': RATING_HIGH,
        'description': "An NVIDIA Triton Inference Server appears to be exposed to the internet, identified via its API root response. Triton has no authentication by default, allowing anyone to enumerate and run inference against every model it serves.",
        'remediation': "Restrict access to Triton's HTTP/gRPC ports to a VPN/trusted network or place it behind an authenticating API gateway.",
    },
    {
        'name': 'TensorFlow Serving', 'ports': [8501], 'paths': ['/v1/models/twigs-nonexistent-probe'],
        'status_codes': [404], 'body_contains_any': ['Servable not found for request'], 'not_html': True, 'rating': RATING_MEDIUM,
        'description': "A TensorFlow Serving instance appears to be exposed to the internet, identified via its distinctive model-not-found error wording. No model name was confirmed by this probe alone, but the REST API itself has no authentication by default - anyone who learns or guesses a loaded model's name can run inference against it directly.",
        'remediation': "Restrict access to TensorFlow Serving's REST/gRPC ports to a VPN/trusted network or place it behind an authenticating API gateway.",
    },
    {
        'name': 'ChromaDB', 'ports': [8000, 8001], 'paths': ['/api/v1/heartbeat', '/api/v2/heartbeat'],
        'body_contains_any': ['nanosecond heartbeat'], 'not_html': True, 'rating': RATING_HIGH,
        'description': "A ChromaDB vector database instance appears to be exposed to the internet, identified via its heartbeat API. Chroma has no authentication by default, allowing anyone who enumerates a collection name (trivially discoverable via its own API) to read or write the embeddings/documents it stores - often the retrieval corpus behind a RAG/LLM application, which can include proprietary or sensitive source data.",
        'remediation': "Restrict access to ChromaDB to a VPN/trusted network, or enable its static-token/basic-auth authentication provider before exposing it beyond localhost.",
    },
    {
        'name': 'Qdrant', 'ports': [6333], 'paths': ['/'],
        'body_contains_any': ['qdrant - vector search engine'], 'not_html': True, 'rating': RATING_HIGH,
        'description': "A Qdrant vector database instance appears to be exposed to the internet, identified via its root API response. Qdrant has no authentication by default, allowing anyone to read or write any collection - typically the retrieval corpus behind a RAG/LLM application.",
        'remediation': "Restrict access to Qdrant to a VPN/trusted network, or set the api-key configuration option before exposing it beyond localhost.",
    },
    {
        'name': 'Weaviate', 'ports': [8080], 'paths': ['/v1/meta'],
        'body_contains_all': ['"hostname"', '"modules"'], 'not_html': True, 'rating': RATING_HIGH,
        'description': "A Weaviate vector database instance appears to be exposed to the internet, identified via its /v1/meta endpoint. Weaviate has no authentication by default (anonymous access enabled), allowing anyone to read or write any class/object - typically the retrieval corpus behind a RAG/LLM application.",
        'remediation': "Restrict access to Weaviate to a VPN/trusted network, or disable AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED and configure an authentication scheme (API key or OIDC) before exposing it beyond localhost.",
    },
    {
        'name': 'Milvus (metrics endpoint)', 'ports': [9091], 'paths': ['/metrics'],
        'body_contains_any': ['milvus_proxy_', 'milvus_rootcoord_', 'milvus_datacoord_'], 'rating': RATING_HIGH,
        'description': "A Milvus vector database's metrics endpoint appears to be exposed to the internet, confirming a Milvus deployment (typically backing a RAG/LLM application) is reachable. Milvus's own gRPC API (default port 19530) commonly has no authentication enabled by default and is worth confirming separately.",
        'remediation': "Restrict access to Milvus's ports (metrics on 9091, API on 19530) to a VPN/trusted network, and enable Milvus's authentication (common.security.authorizationEnabled) before exposing it beyond localhost.",
    },
]


def _probe_specs(check):
    """All (port, path, scheme) combinations to try for one check, in the
    deterministic order a match should be preferred in."""
    return [(port, path, scheme)
            for port in check['ports'] for path in check['paths'] for scheme in ('http', 'https')]


def check_self_hosted_ai(host, asset_id):
    issues = []
    found = []

    # Every (check, port, path, scheme) combination across every check in the
    # catalog is submitted up front and run concurrently with a short,
    # aggressive timeout: most of these ports are closed/filtered on the
    # overwhelming majority of targets, so probing them one at a time (as a
    # plain sequential loop) spends nearly all of its wall-clock time waiting
    # out the same timeout over and over. A real service on one of these
    # ports responds almost instantly, so a short timeout here does not risk
    # missing a genuine match.
    specs_by_check = {id(check): _probe_specs(check) for check in AI_SERVICE_CHECKS}
    responses = {}  # (id(check), port, path, scheme) -> resp
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
        future_to_key = {}
        for check in AI_SERVICE_CHECKS:
            for port, path, scheme in specs_by_check[id(check)]:
                url = '%s://%s:%s%s' % (scheme, host, port, path)
                fut = pool.submit(_http_get, url, PROBE_TIMEOUT_SHORT)
                future_to_key[fut] = (id(check), port, path, scheme)
        for fut in as_completed(future_to_key):
            responses[future_to_key[fut]] = fut.result()

    for check in AI_SERVICE_CHECKS:
        status_codes = check.get('status_codes', [200])
        match = None
        for port, path, scheme in specs_by_check[id(check)]:
            resp = responses.get((id(check), port, path, scheme))
            if resp is None or resp.status_code not in status_codes:
                continue
            if not _panel_signature_matches(resp, check):
                continue
            match = (scheme, port, path)
            break  # first matching port/path for this check is enough
        if match is None:
            continue
        scheme, port, path = match
        found.append('%s (port %s)' % (check['name'], port))
        issues.append(_new_issue(
            'shadow-ai-exposed-%s' % re.sub(r'[^a-z0-9]+', '-', check['name'].lower()).strip('-'),
            "Exposed self-hosted AI infrastructure: %s" % check['name'],
            "%s Found at [%s://%s:%s%s]." % (check['description'], scheme, host, port, path),
            check['rating'], asset_id, ISSUE_TYPE_SHADOW_AI, object_id='%s:%s' % (host, port),
            remediation=check['remediation']))

    if not found:
        issues.append(_new_issue(
            'shadow-ai-exposed-none-found', "No exposed self-hosted AI/LLM infrastructure detected",
            "Checked [%s] known self-hosted LLM inference server / vector database signatures (Ollama, OpenAI-API-compatible servers, Open WebUI, text-generation-webui, Triton, TensorFlow Serving, ChromaDB, Qdrant, Weaviate, Milvus) against [%s] on their common ports and found none exposed." % (len(AI_SERVICE_CHECKS), host),
            RATING_INFO, asset_id, ISSUE_TYPE_SHADOW_AI, object_id=host,
            remediation="No action required. This checks a curated, high-confidence signature list on commonly-used default ports, not an exhaustive one - periodic re-scanning is still worthwhile as new self-hosted AI tooling gets deployed."))
    return issues
