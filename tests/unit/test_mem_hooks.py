from __future__ import annotations

from hooks.mem_hooks import MAX_SNAPSHOT_SIZE, WriteTracker

def test_write_tracker_coalescing():
    """
    Test that WriteTracker properly coalesces adjacent and overlapping writes.
    """
    tracker = WriteTracker()

    # 1. Simulate byte-by-byte write (like a decryptor loop)
    _ = tracker.add_write(0x1000, 1)
    _ = tracker.add_write(0x1001, 1)
    _ = tracker.add_write(0x1002, 1)
    _ = tracker.add_write(0x1003, 1)

    regions = tracker.get_regions()
    assert len(regions) == 1
    assert regions[0] == (0x1000, 0x1004)

    # 2. Write to a completely disconnected region
    _ = tracker.add_write(0x2000, 4)
    regions = tracker.get_regions()
    assert len(regions) == 2
    assert regions[0] == (0x1000, 0x1004)
    assert regions[1] == (0x2000, 0x2004)

    # 3. Overlapping write to the first region
    _ = tracker.add_write(0x1002, 4)  # End becomes 0x1006
    regions = tracker.get_regions()
    assert len(regions) == 2
    assert (0x1000, 0x1006) in regions

def test_write_tracker_max_lookup():
    """
    Verify that if we exceed the O(1) buffer lookup (10 elements), it just appends rather than scanning the whole list.
    """
    tracker = WriteTracker()

    # Create 11 disconnected regions
    for i in range(12):
        _ = tracker.add_write(i * 0x1000, 4)

    regions = tracker.get_regions()
    assert len(regions) == 12

    # Write adjacent to the very first region (index 0).
    # Because it only looks back 10 elements max, it should NOT coalesce, but add a new region.
    _ = tracker.add_write(0x0004, 4) # adjacent to region 0 (0, 4)
    regions2 = tracker.get_regions()
    assert len(regions2) == 13
    assert (0x0004, 0x0008) in regions2


def test_write_tracker_count_increments_on_coalesce():
    """
    Test that count increments each time a write coalesces into an existing region.
    """
    tracker = WriteTracker()

    # Single write → count = 1
    _ = tracker.add_write(0x1000, 4)
    assert tracker.regions[0][2] == 1

    # Adjacent write coalesces → count becomes 2
    _ = tracker.add_write(0x1004, 4)
    assert tracker.regions[0][2] == 2

    # Overlapping write coalesces → count becomes 3
    _ = tracker.add_write(0x1002, 4)
    assert tracker.regions[0][2] == 3

    # Disconnected write → new region with count = 1
    _ = tracker.add_write(0x2000, 4)
    assert len(tracker.regions) == 2
    assert tracker.regions[1][2] == 1


def test_write_tracker_is_hot():
    """
    Test that is_hot() detects regions exceeding the count threshold.
    """
    tracker = WriteTracker()

    # No regions → not hot
    assert tracker.is_hot() is False

    # Single writes below threshold → not hot
    for _ in range(50):
        _ = tracker.add_write(0x1000, 4)
    # 50 writes to same region + 1 from the coalesce loop (49 coalesces after first write)
    # Actually: first write = count 1, then 49 coalesces of adjacent writes
    # Total count = 50 (1 initial + 49 coalesce increments)
    assert tracker.is_hot(threshold=100) is False

    # Push past threshold
    for _ in range(51):
        _ = tracker.add_write(0x1000, 4)
    # Now count = 101
    assert tracker.is_hot() is True


def test_write_tracker_get_regions_backwards_compat():
    """
    Test that get_regions() still returns (start, end) tuples for backwards compatibility.
    """
    tracker = WriteTracker()
    _ = tracker.add_write(0x1000, 4)
    _ = tracker.add_write(0x2000, 4)

    regions = tracker.get_regions()

    # Must be tuples, not lists
    for r in regions:
        assert isinstance(r, tuple)
        assert len(r) == 2
        assert all(isinstance(v, int) for v in r)

    # Values must match expected
    assert (0x1000, 0x1004) in regions
    assert (0x2000, 0x2004) in regions


def test_write_tracker_isolated_regions_count_independently():
    """
    Test that disconnected regions maintain independent counts and
    don't bloat endlessly from far-away writes.
    """
    tracker = WriteTracker()

    # Create three disconnected regions with varying activity
    for _ in range(5):
        _ = tracker.add_write(0x1000, 4)    # 5 coalesces → count 5
    for _ in range(3):
        _ = tracker.add_write(0x2000, 4)    # 3 coalesces → count 3
    for _ in range(10):
        _ = tracker.add_write(0x3000, 4)    # 10 coalesces → count 10

    # Verify each region has its own count
    counts = {}
    for r in tracker.regions:
        start = r[0]
        count = r[2]
        counts[start] = count

    assert counts[0x1000] == 5
    assert counts[0x2000] == 3
    assert counts[0x3000] == 10


def test_write_tracker_keeps_overwritten_candidates_for_same_address():
    """
    Test that candidate history retains overwritten strings for one address.
    """
    tracker = WriteTracker()

    _ = tracker.add_candidate(0x4000, b"first_secret")
    _ = tracker.add_candidate(0x4000, b"second_secret")

    assert tracker.get_candidates() == [(0x4000, b"first_secret"), (0x4000, b"second_secret")]
    assert tracker.get_regions() == []


def test_write_tracker_candidate_history_is_bounded():
    """
    Test that candidate history evicts old snapshots at the configured cap.
    """
    tracker = WriteTracker(max_candidate_history=2)

    _ = tracker.add_candidate(0x4000, b"first_secret")
    _ = tracker.add_candidate(0x4000, b"second_secret")
    _ = tracker.add_candidate(0x4000, b"third_secret")

    assert tracker.get_candidates() == [(0x4000, b"second_secret"), (0x4000, b"third_secret")]


def test_write_tracker_candidate_bytes_are_capped():
    """
    Test that a single candidate cannot retain unbounded raw bytes.
    """
    tracker = WriteTracker()

    _ = tracker.add_candidate(0x5000, b"A" * (MAX_SNAPSHOT_SIZE + 10))

    [(address, data)] = tracker.get_candidates()
    assert address == 0x5000
    assert len(data) == MAX_SNAPSHOT_SIZE
