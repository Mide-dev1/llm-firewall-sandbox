"""
Quick sanity check that the Ollama client can actually reach your local
Ollama server and get a real response back.

Run:
    python scripts/test_ollama_connection.py
"""

from firewall.ollama_client import chat


def main() -> None:
    print("Sending a test message to Ollama ...")
    reply = chat(
        [{"role": "user", "content": "Reply with exactly: connection ok"}])
    print(f"\nModel replied: {reply}")


if __name__ == "__main__":
    main()
