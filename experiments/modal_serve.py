import subprocess
import modal

MODEL = "Qwen/Qwen2.5-7B-Instruct"   # benign executor + weak monitor
SERVED_NAME = "small"                # must match MODEL_SMALL in experiments/.env
PORT = 8000

image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("vllm", "huggingface_hub[hf_transfer]")
    .env({
        "HF_HUB_ENABLE_HF_TRANSFER": "1",
        # Use vLLM's native PyTorch sampler. The FlashInfer sampler JIT-compiles
        # CUDA kernels and needs nvcc, which this image doesn't have.
        "VLLM_USE_FLASHINFER_SAMPLER": "0",
    })
)

hf_cache = modal.Volume.from_name("hf-cache", create_if_missing=True)
vllm_cache = modal.Volume.from_name("vllm-cache", create_if_missing=True)

app = modal.App("aguard-vllm")


@app.function(
    image=image,
    gpu="A10G",                      # use "L4" if A10G is queued
    scaledown_window=300,            # 5 idle minutes before the container stops
    timeout=900,
    volumes={
        "/root/.cache/huggingface": hf_cache,
        "/root/.cache/vllm": vllm_cache,
    },
)
@modal.concurrent(max_inputs=16)
@modal.web_server(port=PORT, startup_timeout=900, requires_proxy_auth=True)
def serve():
    subprocess.Popen([
        "vllm", "serve", MODEL,
        "--served-model-name", SERVED_NAME,
        "--host", "0.0.0.0",
        "--port", str(PORT),
        "--max-model-len", "8192",
        "--gpu-memory-utilization", "0.90",
        "--enable-auto-tool-choice",
        "--tool-call-parser", "hermes",
        "--enforce-eager",           # skips torch.compile/CUDA graphs: faster, safer cold start
    ])