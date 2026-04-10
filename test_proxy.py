import asyncio
import httpx
import time
import subprocess
import sys
import os

async def run_test():
    print("Starting server...")
    # Start the server as a subprocess
    server_process = subprocess.Popen(
        [sys.executable, "main.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"}
    )
    
    # Wait for server to start
    time.sleep(3)
    
    print("Sending test request...")
    payload = {
        "model": "gpt-3.5-turbo", 
        "messages": [
            {
                "role": "user", 
                "content": "Please optimize this code. My email is qiaosec@gmail.com and my AWS key is AKIAIOSFODNN7EXAMPLE."
            }
        ]
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://127.0.0.1:8000/v1/chat/completions",
                json=payload,
                headers={"Authorization": "Bearer fake_key_for_testing"}
            )
            print(f"Response status: {response.status_code}")
            print(f"Response body: {response.text}")
    except Exception as e:
        print(f"Request failed: {e}")
        
    print("Terminating server...")
    server_process.terminate()
    server_process.wait(timeout=5)
    
    print("Server output:")
    stdout, stderr = server_process.communicate()
    print("STDOUT:", stdout)
    print("STDERR:", stderr)

if __name__ == "__main__":
    asyncio.run(run_test())
