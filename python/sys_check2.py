import psutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

EXTREME_CPU = 4
HIGH_CPU = 3
MID_CPU = 2
LOW_CPU = 1

EXTREME_RAM = 4200 
HIGH_RAM = 3600 
MID_RAM = 2400 
LOW_RAM = 1600 

EXTREME_STORAGE = 5000 
HIGH_STORAGE = 3000 
MID_STORAGE = 1000 
LOW_STORAGE = 500 

EXTREME_ENCRYPTION = Cipher(algorithms.AES(b'\x00' * 24), modes.GCM(b'\x00' * 16)) 
HIGH_ENCRYPTION = Cipher(algorithms.AES(b'\x00' * 16), modes.CBC(b'\x00' * 16)) 
MID_ENCRYPTION = Cipher(algorithms.ChaCha20(b'\x00' * 32, b'\x00' * 16), mode=None) 
LOW_ENCRYPTION = None

EXTREME_DELETION = 'RCMP TSSIT OPS-II' 
HIGH_DELETION = 'DoD 5220.22-M' 
MID_DELETION = 'NCSC-TG-025' 
LOW_DELETION = 'Random overwrite pass' 

def get_cpu_speed():
    freq = psutil.cpu_freq(percpu=True)[0].current
    return freq / 1000

def get_ram_speed():
    total_ram = psutil.virtual_memory().total
    ram_usage = psutil.virtual_memory().percent
    ram_bandwidth = (total_ram * ram_usage) / 100
    return (ram_bandwidth / (1024 * 1024)) * 8

def get_storage_speed():
    disk_usage = psutil.disk_usage('/')
    disk_io = psutil.disk_io_counters(perdisk=False)
    storage_speed = (disk_io.read_bytes + disk_io.write_bytes) / disk_usage.total
    return storage_speed * (1024 * 1024)

def assign_tier(value, thresholds):
    thresholds.sort(reverse=True)
    for i, threshold in enumerate(thresholds):
        if value >= threshold:
            return ['Extreme', 'High', 'Mid', 'Low'][i], i
    return 'Unknown', -1

def recommend_encryption(tier_index):
    return [EXTREME_ENCRYPTION, HIGH_ENCRYPTION, MID_ENCRYPTION, LOW_ENCRYPTION][tier_index]

def recommend_deletion(tier_index):
    return [EXTREME_DELETION, HIGH_DELETION, MID_DELETION, LOW_DELETION][tier_index]

# Define a function to get the algorithm name from a Cipher object
def get_algorithm_name(cipher):
    # Check if the cipher object is None
    if cipher is None:
        # Return 'No encryption algorithm'
        return 'No encryption algorithm'
    # Otherwise, proceed as before
    else:
        # Get the key and mode attributes of the cipher
        key = cipher.algorithm.key
        mode = cipher.mode
        # Check if the cipher is AES-256 with HMAC-SHA256 authentication
        if isinstance(cipher.algorithm, algorithms.AES) and len(key) == 32 and isinstance(mode, modes.GCM):
            return 'AES-256 with HMAC-SHA256 authentication'
        # Check if the cipher is AES-192 with GCM mode
        elif isinstance(cipher.algorithm, algorithms.AES) and len(key) == 24 and isinstance(mode, modes.GCM):
            return 'AES-192 with GCM mode'
        # Check if the cipher is AES-128 with CBC mode
        elif isinstance(cipher.algorithm, algorithms.AES) and len(key) == 16 and isinstance(mode, modes.CBC):
            return 'AES-128'
        else:
            return 'AES-128'

cpu_speed = get_cpu_speed()
ram_speed = get_ram_speed()
storage_speed = get_storage_speed()

cpu_tier, cpu_index = assign_tier(cpu_speed, [EXTREME_CPU, HIGH_CPU, MID_CPU, LOW_CPU])
ram_tier, ram_index = assign_tier(ram_speed, [EXTREME_RAM, HIGH_RAM, MID_RAM, LOW_RAM])
storage_tier, storage_index = assign_tier(storage_speed, [EXTREME_STORAGE, HIGH_STORAGE, MID_STORAGE, LOW_STORAGE])

encryption_index = min(cpu_index, ram_index, storage_index)
encryption_algorithm = recommend_encryption(encryption_index)

deletion_index = max(cpu_index, ram_index, storage_index)
deletion_algorithm = recommend_deletion(deletion_index)

print(f"Your system's CPU speed is {cpu_speed:.2f} GHz, which is {cpu_tier} tier.")
print(f"Your system's RAM speed is {ram_speed:.2f} MHz, which is {ram_tier} tier.")
print(f"Your system's storage read/write speed is {storage_speed:.2f} MB/s, which is {storage_tier} tier.")
print(f"The recommended encryption algorithm for your system is {get_algorithm_name(encryption_algorithm)}.")
print(f"The recommended deletion algorithm for your system is {deletion_algorithm}.")
