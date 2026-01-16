import time
import psutil
import numpy as np
import csv
import gc
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
ITERATIONS = 50
KEM_ALG = "Kyber512"
CSV_FILENAME = "correct_hybrid_benchmark.csv"

# --- Helper Functions ---
def memory_usage_kb():
    process = psutil.Process()
    return process.memory_info().rss / 1024

def kdf(secret1, secret2):
    """Key derivation function to combine secrets"""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(secret1)
    digest.update(secret2)
    return digest.finalize()

def benchmark_correct_hybrid(global_counter_start, csv_writer):
    """Correct measurement of hybrid key exchange latency"""
    times, mem_usages = [], []
    process_id = global_counter_start

    for i in range(ITERATIONS):
        label = f"{process_id} HYBRID X25519+{KEM_ALG}"
        print(f"Running iteration: {label}")

        gc.collect()
        start_mem = memory_usage_kb()
        start = time.perf_counter()

        # --- RECEIVER SETUP (Long-term keys) ---
        # This is typically done once and reused, but we include for completeness
        receiver_classical_priv = x25519.X25519PrivateKey.generate()
        receiver_classical_pub = receiver_classical_priv.public_key()
        
        # Receiver's KEM object with keypair
        receiver_kem = oqs.KeyEncapsulation(KEM_ALG)
        receiver_public_key = receiver_kem.generate_keypair()  # Private key stored internally
        
        # Serialize public keys for transmission
        receiver_classical_pub_bytes = receiver_classical_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # --- SENDER OPERATIONS ---
        # 1. Generate ephemeral classical key
        sender_classical_priv = x25519.X25519PrivateKey.generate()
        sender_classical_pub = sender_classical_priv.public_key()
        sender_classical_pub_bytes = sender_classical_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # 2. Classical ECDH
        classical_shared_sender = sender_classical_priv.exchange(
            x25519.X25519PublicKey.from_public_bytes(receiver_classical_pub_bytes)
        )
        
        # 3. PQ Encapsulation
        sender_kem = oqs.KeyEncapsulation(KEM_ALG)
        kem_ciphertext, pq_shared_sender = sender_kem.encap_secret(receiver_public_key)
        sender_kem.free()
        
        # 4. Combine secrets (sender side)
        sender_hybrid_secret = kdf(classical_shared_sender, pq_shared_sender)
        
        # --- RECEIVER OPERATIONS (using same KEM object) ---
        # 5. Classical ECDH (receiver side)
        classical_shared_receiver = receiver_classical_priv.exchange(
            x25519.X25519PublicKey.from_public_bytes(sender_classical_pub_bytes)
        )
        
        # 6. PQ Decapsulation (using the same receiver_kem object)
        pq_shared_receiver = receiver_kem.decap_secret(kem_ciphertext)
        
        # 7. Combine secrets (receiver side)
        receiver_hybrid_secret = kdf(classical_shared_receiver, pq_shared_receiver)
        
        # 8. VERIFY
        if sender_hybrid_secret != receiver_hybrid_secret:
            print(f"ERROR: Secrets don't match in iteration {i}!")
        
        # Clean up
        receiver_kem.free()
        
        end = time.perf_counter()
        total_time = (end - start) * 1000
        mem_usage = memory_usage_kb() - start_mem
        
        times.append(total_time)
        mem_usages.append(mem_usage)
        
        csv_writer.writerow([
            process_id,
            f"X25519 + {KEM_ALG}",
            f"{total_time:.4f}",
            f"{mem_usage:.4f}",
            str(sender_hybrid_secret == receiver_hybrid_secret)
        ])
        
        # Force cleanup
        del receiver_classical_priv, receiver_kem, sender_classical_priv, sender_kem
        gc.collect()
        
        process_id += 1
    
    return {
        "mean_time": np.mean(times),
        "std_time": np.std(times),
        "mean_mem": np.mean(mem_usages),
        "next_process_id": process_id
    }

# --- Alternative: Simplified KEM-only benchmark ---
def benchmark_kem_only(csv_writer):
    """Benchmark just the KEM operations (sender + receiver)"""
    times, mem_usages = [], []
    
    for i in range(ITERATIONS):
        gc.collect()
        start_mem = memory_usage_kb()
        start = time.perf_counter()
        
        # Receiver sets up KEM
        receiver = oqs.KeyEncapsulation(KEM_ALG)
        pk = receiver.generate_keypair()  # Generates and stores keypair
        
        # Sender encapsulates
        sender = oqs.KeyEncapsulation(KEM_ALG)
        ciphertext, sender_secret = sender.encap_secret(pk)
        sender.free()
        
        # Receiver decapsulates
        receiver_secret = receiver.decap_secret(ciphertext)
        receiver.free()
        
        # Verify
        if sender_secret != receiver_secret:
            print(f"ERROR: KEM secrets don't match in iteration {i}!")
        
        end = time.perf_counter()
        total_time = (end - start) * 1000
        mem_usage = memory_usage_kb() - start_mem
        
        times.append(total_time)
        mem_usages.append(mem_usage)
    
    return np.mean(times), np.mean(mem_usages)

# --- Run Benchmark ---
print("Running Correct Hybrid Benchmark (X25519 + Kyber512)\n")

with open(CSV_FILENAME, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow([
        "Process ID",
        "Algorithm",
        "Total Time (ms)",
        "Mem (KB)",
        "Success"
    ])
    
    result = benchmark_correct_hybrid(1, writer)
    
    # Optional: Run KEM-only for comparison
    # kem_time, kem_mem = benchmark_kem_only(writer)

# --- Summary ---
print("\n--- SUMMARY RESULTS ---")
print(f"{'Algorithm':<30} {'Time (ms)':<15} {'Mem (KB)':<10}")
print("-" * 60)
print(f"{'X25519 + Kyber512':<30} "
      f"{result['mean_time']:<15.2f} "
      f"{result['mean_mem']:<10.2f}")

print(f"\nBenchmark complete. Results saved to '{CSV_FILENAME}'")