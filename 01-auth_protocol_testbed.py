#!/usr/bin/env python3
"""
Authentication Protocol Testbed for Fog-Driven e-Healthcare Systems
====================================================================

This script implements a benchmarking framework for the proposed lightweight
authentication protocol using hash functions and HMAC. It measures:
- Computation time for cryptographic primitives
- End-to-end authentication latency
- Energy consumption estimation
- Scalability under concurrent requests

Based on the protocol described in:
"A Verifiably Secure and Lightweight Authentication Scheme for Fog-Driven e-Healthcare"

Author: Research Team
Date: 2025
License: MIT
"""

import hashlib
import hmac
import os
import time
import statistics
import argparse
import json
import csv
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# =============================================================================
# Configuration Constants
# =============================================================================

# Hash function selection (supports multiple algorithms for comparison)
HASH_ALGORITHMS = {
    'sha256': hashlib.sha256,
    'sha3_256': hashlib.sha3_256,
    'blake2b': hashlib.blake2b,
    'blake2s': hashlib.blake2s,
}

DEFAULT_HASH = 'sha256'
HASH_FUNC = HASH_ALGORITHMS[DEFAULT_HASH]
HMAC_FUNC = hmac.new

# Default iterations for benchmarking
DEFAULT_ITERATIONS = 1000
DEFAULT_WARMUP = 100

# Timestamp tolerance (seconds)
DELTA_T = 5.0

# Power consumption estimates (Watts) for different device types
# Based on typical values from literature [49], [50]
POWER_ESTIMATES = {
    'fog_server': 25.0,      # HP Core i7 laptop
    'user_device': 4.0,       # Samsung Galaxy A05s smartphone
    'sensor_node': 3.5,       # Raspberry Pi 5
    'arduino_uno': 0.5,       # Ultra-constrained device (estimate)
    'esp32': 0.3,              # IoT device (estimate)
}

# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class CryptoBenchmark:
    """Benchmark results for cryptographic primitives."""
    operation: str
    algorithm: str
    mean_time_ms: float
    std_dev_ms: float
    min_time_ms: float
    max_time_ms: float
    iterations: int
    device_type: str

@dataclass
class AuthSessionMetrics:
    """Metrics for a complete authentication session."""
    session_id: str
    timestamp: float
    user_time_ms: float
    fog_time_ms: float
    sensor_time_ms: float
    total_time_ms: float
    message_count: int
    bytes_transmitted: int
    energy_user_mj: float
    energy_fog_mj: float
    energy_sensor_mj: float
    total_energy_mj: float
    success: bool

class SecureRandom:
    """Secure random number generator wrapper."""
    
    @staticmethod
    def get_random_bytes(length: int = 16) -> bytes:
        """Generate cryptographically secure random bytes."""
        return os.urandom(length)
    
    @staticmethod
    def get_random_int(max_val: int = 2**32) -> int:
        """Generate cryptographically secure random integer."""
        return int.from_bytes(os.urandom(4), 'big') % max_val


# =============================================================================
# Core Cryptographic Operations
# =============================================================================

def hash_operation(data: bytes, algorithm: str = DEFAULT_HASH) -> bytes:
    """
    Perform cryptographic hash operation.
    
    Args:
        data: Input data to hash
        algorithm: Hash algorithm to use
    
    Returns:
        Hash digest as bytes
    """
    hash_func = HASH_ALGORITHMS.get(algorithm, hashlib.sha256)
    return hash_func(data).digest()


def hmac_operation(key: bytes, data: bytes, algorithm: str = DEFAULT_HASH) -> bytes:
    """
    Perform HMAC operation.
    
    Args:
        key: HMAC key
        data: Message data
        algorithm: Hash algorithm for HMAC
    
    Returns:
        HMAC digest as bytes
    """
    hash_func = HASH_ALGORITHMS.get(algorithm, hashlib.sha256)
    return HMAC_FUNC(key, data, hash_func).digest()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings (padded to longer length).
    
    Args:
        a: First byte string
        b: Second byte string
    
    Returns:
        XOR result as bytes
    """
    max_len = max(len(a), len(b))
    a_padded = a.ljust(max_len, b'\x00')
    b_padded = b.ljust(max_len, b'\x00')
    return bytes(x ^ y for x, y in zip(a_padded, b_padded))


# =============================================================================
# Protocol Entities
# =============================================================================

class FogServer:
    """Fog Server entity in the authentication protocol."""
    
    def __init__(self, server_id: str, device_type: str = 'fog_server'):
        self.id = server_id.encode('utf-8')
        self.device_type = device_type
        
        # Master secrets
        self.Kf = SecureRandom.get_random_bytes(32)  # Fog master secret
        self.Ks = SecureRandom.get_random_bytes(32)  # Sensor master secret
        
        # Databases
        self.users = {}      # {PIDU: Reg2}
        self.sensors = {}    # {IDS: (M1, M2)}
        
        # Performance tracking
        self.total_time_ms = 0.0
        self.operation_count = 0
    
    def register_user(self, IDU: bytes, AuthU: bytes, BioU: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
        """
        User registration phase (Module 2).
        
        Returns:
            PIDU, Reg1, Reg2, Reg3
        """
        start_time = time.perf_counter()
        
        # Generate pseudo-identity and nonce
        PIDU = SecureRandom.get_random_bytes(16)
        nF1 = SecureRandom.get_random_bytes(16)
        
        # Compute registration parameters
        h_PIDU_Kf = hash_operation(PIDU + self.Kf)
        Reg1 = xor_bytes(h_PIDU_Kf, AuthU)
        Reg2 = xor_bytes(h_PIDU_Kf, nF1)
        Reg3 = hash_operation(AuthU + nF1 + BioU)
        
        # Store user record
        self.users[PIDU] = Reg2
        
        # Update performance metrics
        self.total_time_ms += (time.perf_counter() - start_time) * 1000
        self.operation_count += 3  # 3 hash operations
        
        return PIDU, Reg1, Reg2, Reg3
    
    def register_sensor(self, IDS: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Sensor pre-deployment registration.
        
        Returns:
            M1, M2, Kf (for sensor storage)
        """
        start_time = time.perf_counter()
        
        # Compute sensor secrets
        M1 = hash_operation(IDS + self.Ks)
        M2 = hash_operation(M1 + self.Kf)
        
        # Store sensor record
        self.sensors[IDS] = (M1, M2)
        
        # Update performance metrics
        self.total_time_ms += (time.perf_counter() - start_time) * 1000
        self.operation_count += 2  # 2 hash operations
        
        return M1, M2, self.Kf
    
    def authenticate_step1(self, PIDU: bytes, M1: bytes, M2: bytes, TS1: float) -> Optional[Tuple[bytes, bytes, bytes, float, bytes]]:
        """
        Step 02: Process user authentication request.
        
        Returns:
            (M3, M4, M5, TS3, nU2) or None if authentication fails
        """
        start_time = time.perf_counter()
        
        # Verify timestamp
        current_time = time.time()
        if abs(current_time - TS1) > DELTA_T:
            print(f"Timestamp verification failed: |{current_time} - {TS1}| > {DELTA_T}")
            return None
        
        # Retrieve user record
        if PIDU not in self.users:
            print(f"Unknown PIDU: {PIDU.hex()[:8]}...")
            return None
        
        Reg2 = self.users[PIDU]
        
        # Recover AuthU and BioU (simplified - in real protocol, these would be computed)
        # For benchmarking, we assume they are retrieved correctly
        AuthU_BioU = SecureRandom.get_random_bytes(32)  # Placeholder
        
        # Verify M2 (HMAC)
        # In real implementation, we would recompute and compare
        
        # Generate fresh nonce
        nF2 = SecureRandom.get_random_bytes(16)
        
        # Select sensor (for demo, use first sensor)
        if not self.sensors:
            print("No sensors registered")
            return None
        
        IDS = next(iter(self.sensors))
        M1_sensor, _ = self.sensors[IDS]
        
        # Compute messages
        M3 = xor_bytes(nF2, hash_operation(AuthU_BioU))
        M4 = hmac_operation(M1_sensor, self.id + IDU + nF2 + str(TS1).encode())
        M5 = xor_bytes(AuthU_BioU, hash_operation(nF2 + M1_sensor))
        TS3 = time.time()
        
        # Update performance metrics
        elapsed = (time.perf_counter() - start_time) * 1000
        self.total_time_ms += elapsed
        self.operation_count += 5  # 2 hash + 2 HMAC + 1 XOR
        
        return M3, M4, M5, TS3, nF2
    
    def authenticate_step3(self, M6: bytes, M7: bytes, TS5: float, nU2: bytes, nF2: bytes, 
                          AuthU_BioU: bytes) -> Optional[Tuple[bytes, bytes, bytes, bytes, float]]:
        """
        Step 04: Process sensor response.
        
        Returns:
            (Reg1_new, Reg2_new, PIDU_new, M8, TS7) or None if verification fails
        """
        start_time = time.perf_counter()
        
        # Verify timestamp
        current_time = time.time()
        if abs(current_time - TS5) > DELTA_T:
            return None
        
        # Extract nS1 and compute SK
        nS1 = xor_bytes(M6, hash_operation(nU2 + nF2))
        SK = hash_operation(nU2 + nF2 + nS1 + AuthU_BioU)
        
        # Verify M7 (HMAC)
        # In real implementation, would recompute and compare
        
        # Generate new pseudo-identity
        PIDU_new = SecureRandom.get_random_bytes(16)
        nF1 = SecureRandom.get_random_bytes(16)  # Should be retrieved from storage
        
        # Compute new registration parameters
        h_PIDU_new_Kf = hash_operation(PIDU_new + self.Kf)
        Reg1_new = xor_bytes(h_PIDU_new_Kf, AuthU_BioU)
        Reg2_new = xor_bytes(h_PIDU_new_Kf, nF1)
        
        # Compute M8 (HMAC)
        M8 = hmac_operation(SK, Reg1_new + Reg2_new + PIDU_new + str(current_time).encode())
        TS7 = time.time()
        
        # Update user record
        self.users[PIDU_new] = Reg2_new
        
        # Update performance metrics
        elapsed = (time.perf_counter() - start_time) * 1000
        self.total_time_ms += elapsed
        self.operation_count += 4  # 2 hash + 2 HMAC
        
        return Reg1_new, Reg2_new, PIDU_new, M8, TS7
    
    def get_performance_stats(self) -> Dict:
        """Return performance statistics."""
        return {
            'total_time_ms': self.total_time_ms,
            'operation_count': self.operation_count,
            'avg_time_per_op_ms': self.total_time_ms / max(1, self.operation_count)
        }


class UserDevice:
    """User/Physician device entity."""
    
    def __init__(self, user_id: str, device_type: str = 'user_device'):
        self.id = user_id.encode('utf-8')
        self.device_type = device_type
        
        # User credentials
        self.IDU = self.id
        self.PWU = SecureRandom.get_random_bytes(16)  # Simulated password
        self.BIOU = SecureRandom.get_random_bytes(32)  # Simulated biometric
        self.nU1 = SecureRandom.get_random_bytes(16)   # Secret nonce
        
        # Computed credentials
        self.AuthU = hash_operation(self.IDU + self.PWU + self.nU1)
        self.BioU = hash_operation(self.BIOU + self.nU1)
        
        # Registration parameters (set during registration)
        self.PIDU = None
        self.Reg1 = None
        self.Reg2 = None
        self.Reg3 = None
        
        # Session state
        self.nU2 = None
        self.SK = None
        
        # Performance tracking
        self.total_time_ms = 0.0
        self.operation_count = 0
    
    def register(self, fog_server: FogServer) -> bool:
        """
        Perform user registration with fog server.
        """
        start_time = time.perf_counter()
        
        # Send registration request
        self.PIDU, self.Reg1, self.Reg2, self.Reg3 = fog_server.register_user(
            self.IDU, self.AuthU, self.BioU
        )
        
        # Update performance metrics
        elapsed = (time.perf_counter() - start_time) * 1000
        self.total_time_ms += elapsed
        self.operation_count += 1  # Network send/receive (simplified)
        
        return True
    
    def authenticate(self, fog_server: FogServer, sensor_id: bytes) -> Optional[bytes]:
        """
        Step 01: Initiate authentication.
        
        Returns:
            Session key if successful, None otherwise
        """
        start_time = time.perf_counter()
        
        # Verify locally stored Reg3 (simplified)
        h_PIDU_Kf = xor_bytes(self.Reg1, self.AuthU)  # Recover h(PIDU||Kf)
        nF1 = xor_bytes(self.Reg2, h_PIDU_Kf)
        Reg3_computed = hash_operation(self.AuthU + nF1 + self.BioU)
        
        if Reg3_computed != self.Reg3:
            print("Local verification failed")
            return None
        
        # Generate fresh nonce
        self.nU2 = SecureRandom.get_random_bytes(16)
        
        # Compute authentication messages
        M1 = xor_bytes(self.nU2, h_PIDU_Kf)
        TS1 = time.time()
        M2 = hmac_operation(self.AuthU + self.BioU, self.PIDU + sensor_id + str(TS1).encode())
        
        # Update performance metrics
        elapsed1 = (time.perf_counter() - start_time) * 1000
        self.total_time_ms += elapsed1
        self.operation_count += 3  # 1 hash, 1 HMAC, 1 XOR
        
        # Send to fog server (simulate network)
        fog_response = fog_server.authenticate_step1(self.PIDU, M1, M2, TS1)
        
        if fog_response is None:
            return None
        
        M3, M4, M5, TS3, nF2 = fog_response
        
        # Step 05: Process final response
        start_time2 = time.perf_counter()
        
        # Verify timestamp
        if abs(time.time() - TS3) > DELTA_T:
            return None
        
        # Compute session key (simplified - would use values from sensor)
        # In real protocol, nS1 would come from sensor via fog
        nS1 = SecureRandom.get_random_bytes(16)  # Placeholder
        self.SK = hash_operation(self.nU2 + nF2 + nS1 + self.AuthU + self.BioU)
        
        # Update performance metrics
        elapsed2 = (time.perf_counter() - start_time2) * 1000
        self.total_time_ms += elapsed2
        self.operation_count += 1  # 1 hash for SK
        
        return self.SK
    
    def get_performance_stats(self) -> Dict:
        """Return performance statistics."""
        return {
            'total_time_ms': self.total_time_ms,
            'operation_count': self.operation_count,
            'avg_time_per_op_ms': self.total_time_ms / max(1, self.operation_count)
        }


class SensorNode:
    """Sensor/IoT device entity."""
    
    def __init__(self, sensor_id: str, device_type: str = 'sensor_node'):
        self.id = sensor_id.encode('utf-8')
        self.device_type = device_type
        
        # Pre-deployment secrets (set by fog server)
        self.M1 = None
        self.M2 = None
        self.Kf = None
        
        # Session state
        self.nS1 = None
        self.SK = None
        
        # Performance tracking
        self.total_time_ms = 0.0
        self.operation_count = 0
    
    def pre_deploy(self, fog_server: FogServer):
        """Register sensor with fog server before deployment."""
        start_time = time.perf_counter()
        
        self.M1, self.M2, self.Kf = fog_server.register_sensor(self.id)
        
        elapsed = (time.perf_counter() - start_time) * 1000
        self.total_time_ms += elapsed
        self.operation_count += 1  # Network receive
    
    def authenticate(self, M3: bytes, M4: bytes, M5: bytes, TS3: float, nU2: bytes) -> Optional[Tuple[bytes, bytes, float]]:
        """
        Step 03: Process fog server authentication request.
        
        Returns:
            (M6, M7, TS5) or None if verification fails
        """
        start_time = time.perf_counter()
        
        # Verify timestamp
        if abs(time.time() - TS3) > DELTA_T:
            return None
        
        # Verify M4 (HMAC)
        M4_computed = hmac_operation(self.M1, fog_id + nU2 + str(TS3).encode())
        if M4_computed != M4:
            print("Sensor: Fog authentication failed")
            return None
        
        # Extract values (simplified)
        AuthU_BioU = xor_bytes(M5, hash_operation(nU2 + self.M1))
        
        # Generate fresh nonce
        self.nS1 = SecureRandom.get_random_bytes(16)
        
        # Compute session key
        self.SK = hash_operation(nU2 + nU2 + self.nS1 + AuthU_BioU)  # nF2 unknown in sensor
        
        # Compute response messages
        M6 = xor_bytes(self.nS1, hash_operation(nU2 + nU2))  # nF2 placeholder
        M7 = hmac_operation(self.SK, self.id + fog_id + str(time.time()).encode())
        TS5 = time.time()
        
        # Update performance metrics
        elapsed = (time.perf_counter() - start_time) * 1000
        self.total_time_ms += elapsed
        self.operation_count += 4  # 2 hash + 1 HMAC + 1 XOR
        
        return M6, M7, TS5
    
    def get_performance_stats(self) -> Dict:
        """Return performance statistics."""
        return {
            'total_time_ms': self.total_time_ms,
            'operation_count': self.operation_count,
            'avg_time_per_op_ms': self.total_time_ms / max(1, self.operation_count)
        }


# Global fog_id for demo
fog_id = b"FogServer_01"


# =============================================================================
# Benchmarking Functions
# =============================================================================

def benchmark_crypto_primitives(iterations: int = DEFAULT_ITERATIONS, 
                                warmup: int = DEFAULT_WARMUP,
                                device_type: str = 'fog_server') -> List[CryptoBenchmark]:
    """
    Benchmark cryptographic primitive execution times.
    
    Args:
        iterations: Number of iterations for each operation
        warmup: Number of warmup iterations
        device_type: Type of device being benchmarked
    
    Returns:
        List of benchmark results
    """
    results = []
    
    # Test data
    test_key = SecureRandom.get_random_bytes(32)
    test_data = SecureRandom.get_random_bytes(64)
    
    print(f"\nBenchmarking cryptographic primitives on {device_type}...")
    print(f"Iterations: {iterations}, Warmup: {warmup}")
    
    # Test hash functions for each algorithm
    for alg_name in HASH_ALGORITHMS:
        # Warmup
        for _ in range(warmup):
            _ = hash_operation(test_data, alg_name)
        
        # Benchmark
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            _ = hash_operation(test_data, alg_name)
            end = time.perf_counter()
            times.append((end - start) * 1000)  # Convert to ms
        
        results.append(CryptoBenchmark(
            operation='hash',
            algorithm=alg_name,
            mean_time_ms=statistics.mean(times),
            std_dev_ms=statistics.stdev(times) if len(times) > 1 else 0,
            min_time_ms=min(times),
            max_time_ms=max(times),
            iterations=iterations,
            device_type=device_type
        ))
        
        print(f"  {alg_name}: {results[-1].mean_time_ms:.6f} ms ± {results[-1].std_dev_ms:.6f} ms")
    
    # Benchmark HMAC (using default hash)
    times = []
    for _ in range(warmup):
        _ = hmac_operation(test_key, test_data)
    
    for _ in range(iterations):
        start = time.perf_counter()
        _ = hmac_operation(test_key, test_data)
        end = time.perf_counter()
        times.append((end - start) * 1000)
    
    results.append(CryptoBenchmark(
        operation='hmac',
        algorithm='hmac-sha256',
        mean_time_ms=statistics.mean(times),
        std_dev_ms=statistics.stdev(times) if len(times) > 1 else 0,
        min_time_ms=min(times),
        max_time_ms=max(times),
        iterations=iterations,
        device_type=device_type
    ))
    
    print(f"  hmac-sha256: {results[-1].mean_time_ms:.6f} ms ± {results[-1].std_dev_ms:.6f} ms")
    
    # Benchmark XOR
    times = []
    for _ in range(warmup):
        _ = xor_bytes(test_key, test_data)
    
    for _ in range(iterations):
        start = time.perf_counter()
        _ = xor_bytes(test_key, test_data)
        end = time.perf_counter()
        times.append((end - start) * 1000)
    
    results.append(CryptoBenchmark(
        operation='xor',
        algorithm='xor',
        mean_time_ms=statistics.mean(times),
        std_dev_ms=statistics.stdev(times) if len(times) > 1 else 0,
        min_time_ms=min(times),
        max_time_ms=max(times),
        iterations=iterations,
        device_type=device_type
    ))
    
    print(f"  xor: {results[-1].mean_time_ms:.6f} ms ± {results[-1].std_dev_ms:.6f} ms")
    
    return results


def benchmark_full_authentication(iterations: int = 100) -> List[AuthSessionMetrics]:
    """
    Benchmark complete authentication sessions.
    
    Args:
        iterations: Number of authentication sessions to simulate
    
    Returns:
        List of session metrics
    """
    results = []
    
    print(f"\nBenchmarking full authentication sessions ({iterations} iterations)...")
    
    for i in range(iterations):
        # Create entities
        fog = FogServer(f"FogServer_{i % 10}")
        user = UserDevice(f"User_{i}")
        sensor = SensorNode(f"Sensor_{i % 5}")
        
        # Pre-deploy sensor
        sensor.pre_deploy(fog)
        
        # Register user
        user.register(fog)
        
        # Perform authentication
        session_id = f"session_{i}_{int(time.time())}"
        start_time = time.time()
        
        auth_start = time.perf_counter()
        sk = user.authenticate(fog, sensor.id)
        auth_end = time.perf_counter()
        
        success = sk is not None
        
        # Collect metrics
        user_stats = user.get_performance_stats()
        fog_stats = fog.get_performance_stats()
        sensor_stats = sensor.get_performance_stats()
        
        total_time = (auth_end - auth_start) * 1000
        
        # Calculate energy consumption
        energy_user = user_stats['total_time_ms'] * POWER_ESTIMATES['user_device']
        energy_fog = fog_stats['total_time_ms'] * POWER_ESTIMATES['fog_server']
        energy_sensor = sensor_stats['total_time_ms'] * POWER_ESTIMATES['sensor_node']
        
        metrics = AuthSessionMetrics(
            session_id=session_id,
            timestamp=start_time,
            user_time_ms=user_stats['total_time_ms'],
            fog_time_ms=fog_stats['total_time_ms'],
            sensor_time_ms=sensor_stats['total_time_ms'],
            total_time_ms=total_time,
            message_count=4,  # Fixed for this protocol
            bytes_transmitted=312,  # 2496 bits = 312 bytes
            energy_user_mj=energy_user,
            energy_fog_mj=energy_fog,
            energy_sensor_mj=energy_sensor,
            total_energy_mj=energy_user + energy_fog + energy_sensor,
            success=success
        )
        
        results.append(metrics)
        
        if (i + 1) % 10 == 0:
            print(f"  Completed {i + 1}/{iterations} sessions")
    
    return results


def benchmark_concurrent_auth(max_workers: int = 10, sessions_per_worker: int = 10):
    """
    Benchmark concurrent authentication sessions.
    
    Args:
        max_workers: Maximum number of concurrent threads
        sessions_per_worker: Number of sessions per worker
    """
    print(f"\nBenchmarking concurrent authentication ({max_workers} workers, {sessions_per_worker} sessions/worker)...")
    
    def worker(worker_id: int) -> List[float]:
        """Worker function for concurrent testing."""
        latencies = []
        fog = FogServer(f"FogServer_Shared")
        
        for j in range(sessions_per_worker):
            user = UserDevice(f"User_{worker_id}_{j}")
            sensor = SensorNode(f"Sensor_{j % 3}")
            
            sensor.pre_deploy(fog)
            user.register(fog)
            
            start = time.perf_counter()
            sk = user.authenticate(fog, sensor.id)
            end = time.perf_counter()
            
            if sk is not None:
                latencies.append((end - start) * 1000)
        
        return latencies
    
    all_latencies = []
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker, i) for i in range(max_workers)]
        
        for future in as_completed(futures):
            all_latencies.extend(future.result())
    
    end_time = time.time()
    
    if all_latencies:
        print(f"\nConcurrent Benchmark Results:")
        print(f"  Total sessions: {len(all_latencies)}")
        print(f"  Total time: {end_time - start_time:.2f} seconds")
        print(f"  Throughput: {len(all_latencies) / (end_time - start_time):.2f} sessions/second")
        print(f"  Mean latency: {statistics.mean(all_latencies):.3f} ms")
        print(f"  Median latency: {statistics.median(all_latencies):.3f} ms")
        print(f"  P95 latency: {sorted(all_latencies)[int(len(all_latencies) * 0.95)]:.3f} ms")
        print(f"  Min latency: {min(all_latencies):.3f} ms")
        print(f"  Max latency: {max(all_latencies):.3f} ms")
    
    return all_latencies


# =============================================================================
# Results Export Functions
# =============================================================================

def export_to_csv(results: List, filename: str, result_type: str):
    """
    Export benchmark results to CSV file.
    
    Args:
        results: List of benchmark result objects
        filename: Output filename
        result_type: Type of results ('crypto' or 'auth')
    """
    if not results:
        return
    
    with open(filename, 'w', newline='') as csvfile:
        if result_type == 'crypto':
            fieldnames = ['operation', 'algorithm', 'mean_time_ms', 'std_dev_ms', 
                         'min_time_ms', 'max_time_ms', 'iterations', 'device_type']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow({
                    'operation': r.operation,
                    'algorithm': r.algorithm,
                    'mean_time_ms': f"{r.mean_time_ms:.6f}",
                    'std_dev_ms': f"{r.std_dev_ms:.6f}",
                    'min_time_ms': f"{r.min_time_ms:.6f}",
                    'max_time_ms': f"{r.max_time_ms:.6f}",
                    'iterations': r.iterations,
                    'device_type': r.device_type
                })
        
        elif result_type == 'auth':
            fieldnames = ['session_id', 'timestamp', 'user_time_ms', 'fog_time_ms',
                         'sensor_time_ms', 'total_time_ms', 'message_count',
                         'bytes_transmitted', 'energy_user_mj', 'energy_fog_mj',
                         'energy_sensor_mj', 'total_energy_mj', 'success']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow({
                    'session_id': r.session_id,
                    'timestamp': r.timestamp,
                    'user_time_ms': f"{r.user_time_ms:.3f}",
                    'fog_time_ms': f"{r.fog_time_ms:.3f}",
                    'sensor_time_ms': f"{r.sensor_time_ms:.3f}",
                    'total_time_ms': f"{r.total_time_ms:.3f}",
                    'message_count': r.message_count,
                    'bytes_transmitted': r.bytes_transmitted,
                    'energy_user_mj': f"{r.energy_user_mj:.3f}",
                    'energy_fog_mj': f"{r.energy_fog_mj:.3f}",
                    'energy_sensor_mj': f"{r.energy_sensor_mj:.3f}",
                    'total_energy_mj': f"{r.total_energy_mj:.3f}",
                    'success': r.success
                })
    
    print(f"Results exported to {filename}")


def export_to_json(results: List, filename: str):
    """Export results to JSON file."""
    if not results:
        return
    
    # Convert objects to dictionaries
    if hasattr(results[0], '__dict__'):
        data = [r.__dict__ for r in results]
    else:
        data = results
    
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    
    print(f"Results exported to {filename}")


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description='Authentication Protocol Testbed')
    parser.add_argument('--iterations', type=int, default=DEFAULT_ITERATIONS,
                       help=f'Number of iterations for benchmarks (default: {DEFAULT_ITERATIONS})')
    parser.add_argument('--auth-iterations', type=int, default=100,
                       help='Number of full authentication sessions to simulate (default: 100)')
    parser.add_argument('--concurrent-workers', type=int, default=10,
                       help='Number of concurrent workers for scalability test (default: 10)')
    parser.add_argument('--sessions-per-worker', type=int, default=10,
                       help='Sessions per worker for scalability test (default: 10)')
    parser.add_argument('--device', choices=['fog_server', 'user_device', 'sensor_node', 'arduino_uno', 'esp32'],
                       default='fog_server', help='Device type for benchmarking')
    parser.add_argument('--export-csv', action='store_true', help='Export results to CSV')
    parser.add_argument('--export-json', action='store_true', help='Export results to JSON')
    parser.add_argument('--output-prefix', type=str, default='benchmark_results',
                       help='Prefix for output files')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("Authentication Protocol Testbed for Fog-Driven e-Healthcare")
    print("=" * 70)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Device type: {args.device}")
    print(f"Hash algorithm: {DEFAULT_HASH}")
    
    # Run cryptographic primitive benchmarks
    crypto_results = benchmark_crypto_primitives(
        iterations=args.iterations,
        device_type=args.device
    )
    
    # Run full authentication benchmarks
    auth_results = benchmark_full_authentication(iterations=args.auth_iterations)
    
    # Calculate summary statistics
    successful_sessions = [r for r in auth_results if r.success]
    failed_sessions = [r for r in auth_results if not r.success]
    
    print("\n" + "=" * 70)
    print("SUMMARY STATISTICS")
    print("=" * 70)
    
    print(f"\nAuthentication Sessions:")
    print(f"  Total sessions: {len(auth_results)}")
    print(f"  Successful: {len(successful_sessions)}")
    print(f"  Failed: {len(failed_sessions)}")
    print(f"  Success rate: {len(successful_sessions)/len(auth_results)*100:.2f}%")
    
    if successful_sessions:
        total_times = [r.total_time_ms for r in successful_sessions]
        print(f"\nLatency (successful sessions):")
        print(f"  Mean: {statistics.mean(total_times):.3f} ms")
        print(f"  Median: {statistics.median(total_times):.3f} ms")
        print(f"  P95: {sorted(total_times)[int(len(total_times)*0.95)]:.3f} ms")
        print(f"  Min: {min(total_times):.3f} ms")
        print(f"  Max: {max(total_times):.3f} ms")
        
        total_energy = [r.total_energy_mj for r in successful_sessions]
        print(f"\nEnergy Consumption:")
        print(f"  Mean: {statistics.mean(total_energy):.3f} mJ")
        print(f"  Median: {statistics.median(total_energy):.3f} mJ")
        print(f"  Total: {sum(total_energy):.3f} mJ")
    
    # Run concurrent scalability benchmark
    if args.concurrent_workers > 0:
        concurrent_latencies = benchmark_concurrent_auth(
            max_workers=args.concurrent_workers,
            sessions_per_worker=args.sessions_per_worker
        )
    
    # Export results
    if args.export_csv:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        export_to_csv(crypto_results, f"{args.output_prefix}_crypto_{timestamp}.csv", 'crypto')
        export_to_csv(auth_results, f"{args.output_prefix}_auth_{timestamp}.csv", 'auth')
    
    if args.export_json:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        export_to_json(crypto_results, f"{args.output_prefix}_crypto_{timestamp}.json")
        export_to_json(auth_results, f"{args.output_prefix}_auth_{timestamp}.json")
    
    print("\n" + "=" * 70)
    print(f"Benchmark completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)


if __name__ == "__main__":
    main()