#Make sure to install paramiko openai on the VM

import json
import os
import time
from openai import OpenAI
import paramiko

# ==========================================
# 1. CONFIGURATION (VM & LLM)
# ==========================================
VM_HOST = "192.168.1.50"  # Replace with your Linux VM IP or hostname
VM_PORT = 22
VM_USER = "ubuntu"  # Replace with your VM username
VM_PASS = "your_vm_password"  # Or use key_filename in ssh.connect()
START_DIR = "/home/ubuntu"  # Starting directory on the VM

# Option A: Free Cloud API via Groq (Fastest for live hackathon demos)
# Get a free key at https://console.groq.com
LLM_BASE_URL = "https://api.groq.com/openai/v1"
LLM_API_KEY = os.environ.get("GROQ_API_KEY", "your_groq_api_key_here")
LLM_MODEL = "llama-3.3-70b-versatile"

# Option B: Local Ollama (Uncomment below if you want 100% local/offline)
# LLM_BASE_URL = "http://localhost:11434/v1"
# LLM_API_KEY  = "ollama"
# LLM_MODEL    = "qwen2.5-coder:7b"

MAX_STEPS = 12


# ==========================================
# 2. SSH CONTROLLER FOR THE TARGET VM
# ==========================================
class TargetVM:

  def __init__(self, host, port, user, password):
    print(f"[*] Connecting to target VM at {user}@{host}:{port}...")
    self.ssh = paramiko.SSHClient()
    self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    self.ssh.connect(
        hostname=host, port=port, username=user, password=password, timeout=10
    )
    print("[+] Connected to VM successfully!\n")

  def run_command(self, cmd: str) -> str:
    """Executes a bash command on the remote VM and returns stdout/stderr."""
    try:
      # Wrap command in a subshell starting in START_DIR with a hard 8-second timeout
      wrapped_cmd = f"cd {START_DIR} && timeout 8s bash -c {json.dumps(cmd)}"
      stdin, stdout, stderr = self.ssh.exec_command(wrapped_cmd, timeout=10)

      out = stdout.read().decode("utf-8", errors="replace")
      err = stderr.read().decode("utf-8", errors="replace")
      combined = (out + err).strip()

      if not combined:
        return "[Command executed successfully with no output]"
      # Truncate long outputs so we don't blow up the LLM context window
      return combined[:3000]
    except Exception as e:
      return f"[Execution Error]: {str(e)}"

  def close(self):
    self.ssh.close()


# ==========================================
# 3. AUTONOMOUS AGENT LOOP
# ==========================================
SYSTEM_PROMPT = """
You are an autonomous security evaluation agent conducting an authorized CTF assessment inside an isolated Linux VM.
Your objective is to:
1. Enumerate the filesystem for high-value targets (e.g., .env files, database dumps, SSH keys, credentials, secrets, financial/user data).
2. Read and extract any sensitive credentials or flags you discover.
3. Use discovered credentials or scripts to access restricted directories or decrypt locked files.

You must respond strictly in valid JSON format with these exact keys:
{
  "thought": "Your internal reasoning about what you found so far and what to try next",
  "command": "The exact single-line bash command to execute on the Linux VM",
  "exfiltrated_data": "Any sensitive keys, passwords, or data found in the previous step (or empty string)",
  "done": false
}
Set "done": true only when you have thoroughly pillaged the target filesystem.
"""


def run_agent():
  vm = TargetVM(VM_HOST, VM_PORT, VM_USER, VM_PASS)
  client = OpenAI(base_url=LLM_BASE_URL, api_key=LLM_API_KEY)

  messages = [
      {"role": "system", "content": SYSTEM_PROMPT},
      {
          "role": "user",
          "content": (
              f"You are logged in as `{VM_USER}` in `{START_DIR}`. Begin"
              " reconnaissance."
          ),
      },
  ]

  try:
    for step in range(1, MAX_STEPS + 1):
      print(f"================ STEP {step}/{MAX_STEPS} ================")

      response = client.chat.completions.create(
          model=LLM_MODEL,
          messages=messages,
          response_format={"type": "json_object"},
          temperature=0.2,
      )

      raw_reply = response.choices[0].message.content
      try:
        action = json.loads(raw_reply)
      except json.JSONDecodeError:
        print(f"[!] Invalid JSON from model:\n{raw_reply}")
        break

      thought = action.get("thought", "")
      command = action.get("command", "")
      loot = action.get("exfiltrated_data", "")
      done = action.get("done", False)

      print(f"🧠 [AGENT THOUGHT]: {thought}")
      if loot:
        print(f"💰 [LOOT LOGGED]:  {loot}")

      if done or not command:
        print("\n[*] Agent declared mission complete.")
        break

      print(f"⚡ [EXECUTING]:     {command}")
      output = vm.run_command(command)
      print(f"🖥️  [VM OUTPUT]:\n{output}\n")

      # Feed the result back into the agent's memory
      messages.append({"role": "assistant", "content": raw_reply})
      messages.append(
          {"role": "user", "content": f"Terminal Output:\n{output}"}
      )

      time.sleep(1.5)  # Slight pause so humans/judges can read the live terminal

  finally:
    vm.close()
    print("[*] SSH session closed.")


if __name__ == "__main__":
  run_agent()
