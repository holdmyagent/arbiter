import os

import pytest

from arbiter.provisioning import ServeLockError, acquire_serve_lock


def test_second_lock_on_same_data_root_refused(cfg):
    fd = acquire_serve_lock(cfg)
    try:
        with pytest.raises(ServeLockError):
            acquire_serve_lock(cfg)     # same root, new fd -> flock refuses
    finally:
        os.close(fd)
    fd2 = acquire_serve_lock(cfg)        # lock dies with the fd -> next start OK
    os.close(fd2)
