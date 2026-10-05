# test_live_ids.py
from modules import log_monitor

if __name__ == "__main__":
    # Use loopback interface for local testing
    log_monitor.start_realtime_monitor(interface="lo")
