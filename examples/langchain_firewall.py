"""
PromptShield Python SDK — LangChain & LlamaIndex Prompt Firewall Example
Protect backend LLM pipelines from processing leaked credentials or customer PII.
"""

from promptshield import PromptFirewall

def main():
    firewall = PromptFirewall(mode="BLOCK")

    # Sample user inputs to test
    prompts = [
        "Explain how the Raft consensus algorithm handles leader election.",
        "Here is my Stripe secret key for our billing system: sk_live_51ABC1234567890DEF",
        "My database URL is postgres://dbadmin:superSecretPass@prod-cluster.rds.amazonaws.com:5432/orders"
    ]

    for p in prompts:
        print(f"\nScanning Prompt: \"{p[:60]}...\"")
        result = firewall.inspect(p)

        if result["allowed"]:
            print("  🟢 PASSED: Safe to send to OpenAI / Claude API")
        else:
            print(f"  🛑 BLOCKED: DLP Rule Triggered -> {result['violations'][0]['rule_name']}")
            print(f"     Severity: {result['violations'][0]['severity']}")

if __name__ == "__main__":
    main()
