import subprocess
import modal

MODEL = "Qwen/Qwen2.5-32B-Instruct-AWQ"
SERVED_NAME = "strong"
PORT = 8000

image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("vllm==0.33.0", "huggingface_hub[hf_transfer]")
    .env({"HF_HUB_ENABLE_HF_TRANSFER": "1", "VLLM_USE_FLASHINFER_SAMPLER": "0"})
)
hf_cache = modal.Volume.from_name("hf-cache", create_if_missing=True)
app = modal.App("aguard-vllm-strong")

@app.function(image=image, gpu="L40S", scaledown_window=300, timeout=1800,
              volumes={"/root/.cache/huggingface": hf_cache})
@modal.concurrent(max_inputs=16)
@modal.web_server(port=PORT, startup_timeout=1800, requires_proxy_auth=True)
def serve():
    subprocess.Popen([
        "vllm", "serve", MODEL, "--served-model-name", SERVED_NAME,
        "--host", "0.0.0.0", "--port", str(PORT),
        "--max-model-len", "8192", "--gpu-memory-utilization", "0.90",
        "--enforce-eager",
    ])
