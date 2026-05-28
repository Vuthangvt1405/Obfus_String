import pytest
from hooks.mem_hooks import WriteTracker

def test_write_tracker_coalescing():
    """
    Test that WriteTracker properly coalesces adjacent and overlapping writes.
    """
    tracker = WriteTracker()
    
    # 1. Simulate byte-by-byte write (like a decryptor loop)
    tracker.add_write(0x1000, 1)
    tracker.add_write(0x1001, 1)
    tracker.add_write(0x1002, 1)
    tracker.add_write(0x1003, 1)
    
    regions = tracker.get_regions()
    assert len(regions) == 1
    assert regions[0] == (0x1000, 0x1004)
    
    # 2. Write to a completely disconnected region
    tracker.add_write(0x2000, 4)
    regions = tracker.get_regions()
    assert len(regions) == 2
    assert regions[0] == (0x1000, 0x1004)
    assert regions[1] == (0x2000, 0x2004)
    
    # 3. Overlapping write to the first region
    tracker.add_write(0x1002, 4)  # End becomes 0x1006
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
        tracker.add_write(i * 0x1000, 4)
        
    regions = tracker.get_regions()
    assert len(regions) == 12
    
    # Write adjacent to the very first region (index 0). 
    # Because it only looks back 10 elements max, it should NOT coalesce, but add a new region.
    tracker.add_write(0x0004, 4) # adjacent to region 0 (0, 4)
    regions2 = tracker.get_regions()
    assert len(regions2) == 13
    assert (0x0004, 0x0008) in regions2
