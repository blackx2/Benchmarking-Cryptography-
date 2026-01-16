import time
import psutil
import numpy as np
import csv
import gc
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# --- Configuration ---
ITERATIONS = 50
MESSAGE = b"This is a test message for RSA benchmarking."
KEY_SIZE = 2048
CSV_FILENAME = "rsa_2048_benchmark.csv"

# --- Helper Functions ---
def memory_usage_kb():
    """Return current process memory usage in KB."""
    process = psutil.Process()
    return process.memory_info().rss / 1024  # bytes → KB

def benchmark_rsa_2048(global_counter_start, csv_writer):
    """Benchmark RSA-2048 key generation, signing, and verification with isolation."""
    keygen_times, sign_times, verify_times, mem_usages = [], [], [], []
    process_id = global_counter_start

    for i in range(ITERATIONS):
        process_label = f"{process_id} RSA {KEY_SIZE}"
        print(f"🔹 Running iteration: {process_label}")

        # --- Force Garbage Collection for Isolation ---
        gc.collect()

        # --- Measure Memory Before ---
        start_mem = memory_usage_kb()

        # --- Key Generation ---
        start = time.perf_counter()
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=KEY_SIZE,
            backend=default_backend()
        )
        end = time.perf_counter()
        keygen_time = (end - start) * 1000  # ms
        keygen_times.append(keygen_time)
        mem_usage = memory_usage_kb() - start_mem
        mem_usages.append(mem_usage)

        public_key = private_key.public_key()

        # --- Signing ---
        start = time.perf_counter()
        signature = private_key.sign(
            MESSAGE,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        end = time.perf_counter()
        sign_time = (end - start) * 1000
        sign_times.append(sign_time)

        # --- Verification ---
        start = time.perf_counter()
        try:
            public_key.verify(
                signature,
                MESSAGE,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            print(f"❌ Verification failed in {process_label}!")
        end = time.perf_counter()
        verify_time = (end - start) * 1000
        verify_times.append(verify_time)

        # --- Write to CSV ---
        csv_writer.writerow([
            process_id,
            KEY_SIZE,
            f"{keygen_time:.4f}",
            f"{sign_time:.4f}",
            f"{verify_time:.4f}",
            f"{mem_usage:.4f}"
        ])

        # --- Cleanup to Prevent Retained References ---
        del private_key, public_key, signature
        gc.collect()

        process_id += 1

    # --- Summary ---
    return {
        "key_size": KEY_SIZE,
        "keygen": np.mean(keygen_times),
        "sign": np.mean(sign_times),
        "verify": np.mean(verify_times),
        "mem": np.mean(mem_usages),
        "keygen_std": np.std(keygen_times),
        "sign_std": np.std(sign_times),
        "verify_std": np.std(verify_times),
        "next_process_id": process_id
    }

# --- Run Benchmark ---
print("Running RSA-2048 Benchmark...\n")
global_process_counter = 1

with open(CSV_FILENAME, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Process ID", "Key Size", "KeyGen (ms)", "Sign (ms)", "Verify (ms)", "Mem (KB)"])
    result = benchmark_rsa_2048(global_process_counter, writer)

# --- Display Summary ---
print("\n--- SUMMARY RESULTS ---")
print(f"{'Algorithm':<15} {'Key Size':<10} {'KeyGen (ms)':<15} {'Sign (ms)':<15} {'Verify (ms)':<15} {'Mem (KB)':<10}")
print("-" * 80)
print(f"{'RSA':<15} {result['key_size']:<10} {result['keygen']:<15.2f} "
      f"{result['sign']:<15.2f} {result['verify']:<15.2f} {result['mem']:<10.2f}")

print(f"\n✅ Benchmark complete. Results saved to '{CSV_FILENAME}'")
