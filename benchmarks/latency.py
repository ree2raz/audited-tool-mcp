import statistics
import time
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from audited_tool_mcp.privacy import detect, use_mock_detector, _get_model

def run_benchmark(iterations: int = 100):
    print("=" * 60)
    print("  Privacy Filter CPU Latency Benchmark")
    print("=" * 60)
    
    # Ensure we use the real model, not the mock
    os.environ["MOCK_PII"] = "0"
    use_mock_detector(False)
    
    print("\n[1/3] Loading 1.5B parameter model (this may take a moment)...")
    model, tokenizer = _get_model()
    
    # Generate a realistic query ~50 tokens long
    query = (
        "SELECT id, first_name, last_name, email, phone, account_number "
        "FROM customers c JOIN accounts a ON c.id = a.customer_id "
        "WHERE first_name = 'John' AND last_name = 'Henderson' "
        "AND email = 'john.henderson@example.com'"
    )
    
    print(f"\n[2/3] Warming up model (1 inference)...")
    # Warmup
    detect(query)
    
    print(f"\n[3/3] Running {iterations} iterations on CPU...")
    
    latencies = []
    
    for i in range(iterations):
        if i > 0 and i % 10 == 0:
            print(f"  Completed {i}/{iterations}...")
            
        start_time = time.perf_counter()
        detections = detect(query)
        end_time = time.perf_counter()
        
        # Ensure it actually detected something to prevent optimizer from skipping work
        assert len(detections) > 0, "Expected PII detections"
        
        latency_ms = (end_time - start_time) * 1000
        latencies.append(latency_ms)
        
    # Calculate metrics
    latencies.sort()
    avg = statistics.mean(latencies)
    p50 = statistics.median(latencies)
    p90 = latencies[int(len(latencies) * 0.90)]
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]
    
    print("\n" + "=" * 60)
    print("  RESULTS (ms)")
    print("=" * 60)
    print(f"  Iterations: {iterations}")
    print(f"  Device:     {model.device}")
    print(f"  Query Size: ~{len(query.split())} words")
    print("-" * 60)
    print(f"  Average:    {avg:.1f} ms")
    print(f"  p50:        {p50:.1f} ms")
    print(f"  p90:        {p90:.1f} ms")
    print(f"  p95:        {p95:.1f} ms")
    print(f"  p99:        {p99:.1f} ms")
    print("=" * 60)


if __name__ == "__main__":
    run_benchmark(100)
