"""
bloom_filter.py
===============
Space-efficient probabilistic data structure to avoid re-hashing
already-attempted password candidates across attack modules.

Uses double hashing (Kirsch-Mitzenmacher technique).
"""

import math
import hashlib
import struct


class BloomFilter:
    """
    Bloom filter for deduplication of password candidates.
    
    Parameters
    ----------
    capacity : int
        Expected number of elements to insert.
    error_rate : float
        Acceptable false positive rate (e.g., 0.001 = 0.1%).
    """

    def __init__(self, capacity: int = 1_000_000, error_rate: float = 0.001):
        self.capacity = capacity
        self.error_rate = error_rate

        # Optimal bit array size and number of hash functions
        self.bit_size = self._optimal_size(capacity, error_rate)
        self.hash_count = self._optimal_hash_count(self.bit_size, capacity)

        # Use bytearray as bit array (bit_size bits)
        self._byte_size = (self.bit_size + 7) // 8
        self._bits = bytearray(self._byte_size)
        self._count = 0

    @staticmethod
    def _optimal_size(n: int, p: float) -> int:
        """m = -n * ln(p) / (ln(2)^2)"""
        return int(-n * math.log(p) / (math.log(2) ** 2)) + 1

    @staticmethod
    def _optimal_hash_count(m: int, n: int) -> int:
        """k = (m/n) * ln(2)"""
        return max(1, int((m / n) * math.log(2)))

    def _get_positions(self, item: str):
        """Generate k bit positions using double hashing."""
        h1 = int(hashlib.md5(item.encode('utf-8', errors='replace')).hexdigest(), 16)
        h2 = int(hashlib.sha1(item.encode('utf-8', errors='replace')).hexdigest(), 16)
        for i in range(self.hash_count):
            yield (h1 + i * h2) % self.bit_size

    def _set_bit(self, pos: int):
        byte_index = pos // 8
        bit_index = pos % 8
        self._bits[byte_index] |= (1 << bit_index)

    def _get_bit(self, pos: int) -> bool:
        byte_index = pos // 8
        bit_index = pos % 8
        return bool(self._bits[byte_index] & (1 << bit_index))

    def add(self, item: str):
        """Add item to filter."""
        for pos in self._get_positions(item):
            self._set_bit(pos)
        self._count += 1

    def __contains__(self, item: str) -> bool:
        """
        Returns True if item was probably added before.
        May have false positives at the configured error rate.
        Never has false negatives.
        """
        return all(self._get_bit(pos) for pos in self._get_positions(item))

    def already_tried(self, candidate: str) -> bool:
        """Returns True if candidate was already attempted. Adds it if not."""
        if candidate in self:
            return True
        self.add(candidate)
        return False

    @property
    def count(self) -> int:
        return self._count

    @property
    def memory_mb(self) -> float:
        return self._byte_size / (1024 * 1024)

    def __repr__(self):
        return (f"BloomFilter(capacity={self.capacity:,}, "
                f"error_rate={self.error_rate}, "
                f"bits={self.bit_size:,}, "
                f"hashes={self.hash_count}, "
                f"memory={self.memory_mb:.2f}MB, "
                f"filled={self._count:,})")
