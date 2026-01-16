import time
import psutil
import numpy as np
import csv
import gc
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
ITERATIONS = 50
SESSION_KEY_SIZE = 32  # 32 bytes = 256-bit session key
KEY_SIZE = 2048
CSV_FILENAME = "rsa_2048_keyexchange_benchmark.csv"

# --- Helper Functions ---
def memory_usage_kb():
    """Return current process memory usage in KB."""
    process = psutil.Process()
    return process.memory_info().rss / 1024

def generate_random_session_key(size=SESSION_KEY_SIZE):
    """Generate a random session key."""
    return np.random.bytes(size)

# --- Benchmark Function ---
def benchmark_rsa_key_exchange(global_counter_start, csv_writer):
    """Benchmark RSA-2048 key exchange (encrypt/decrypt a session key)."""
    times, mem_usages, successes = [], [], []
    process_id = global_counter_start

    # --- Generate long-term RSA key pair (receiver) ---
    receiver_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
        backend=default_backend()
    )
    receiver_public_key = receiver_private_key.public_key()

    for i in range(ITERATIONS):
        label = f"{process_id} RSA {KEY_SIZE} Key Exchange"
        print(f"🔹 Running iteration: {label}")

        gc.collect()
        start_mem = memory_usage_kb()
        start = time.perf_counter()

        # --- Sender generates random session key ---
        session_key = generate_random_session_key()

        # --- Encrypt session key with receiver's public key ---
        ciphertext = receiver_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # --- Receiver decrypts session key ---
        try:
            decrypted_key = receiver_private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            success = (decrypted_key == session_key)
        except Exception:
            success = False

        end = time.perf_counter()
        total_time = (end - start) * 1000  # ms
        mem_usage = memory_usage_kb() - start_mem

        times.append(total_time)
        mem_usages.append(mem_usage)
        successes.append(success)

        # --- Write to CSV ---
        csv_writer.writerow([
            process_id,
            f"RSA-{KEY_SIZE}",
            f"{total_time:.4f}",
            f"{mem_usage:.4f}",
            success
        ])

        gc.collect()
        process_id += 1

    return {
        "mean_time": np.mean(times),
        "std_time": np.std(times),
        "mean_mem": np.mean(mem_usages),
        "success_rate": sum(successes)/len(successes),
        "next_process_id": process_id
    }

# --- Run Benchmark ---
print("Running RSA-2048 Key Exchange Benchmark...\n")

with open(CSV_FILENAME, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow([
        "Process ID",
        "Algorithm",
        "Total Time (ms)",
        "Mem (KB)",
        "Success"
    ])

    result = benchmark_rsa_key_exchange(1, writer)

# --- Summary ---
print("\n--- SUMMARY RESULTS ---")
print(f"{'Algorithm':<15} {'Time (ms)':<15} {'Mem (KB)':<10} {'Success Rate':<10}")
print("-" * 60)
print(f"{'RSA-2048':<15} "
      f"{result['mean_time']:<15.2f} "
      f"{result['mean_mem']:<10.2f} "
      f"{result['success_rate']*100:.2f}%")

print(f"\n✅ Benchmark complete. Results saved to '{CSV_FILENAME}'")
