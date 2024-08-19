import subprocess
import os
import difflib
from concurrent.futures import ThreadPoolExecutor, as_completed

# Define paths and thresholds
DUMPBIN_PATH = "Disassembly\\dumpbin.exe"
NON_ASSEMBLY_FOLDER = "Malware\\nonassembly"
ASSEMBLY_FOLDER = "Malware\\assembly"
LOG_FILE_PATH = "antivirus.log"
SIMILARITY_THRESHOLD = 0.7

def log(message):
    with open(LOG_FILE_PATH, 'a') as log_file:
        log_file.write(f"{message}\n")

def perform_disassembly(file_path):
    try:
        if file_path is None or not os.path.exists(file_path):
            log("Invalid file path.")
            return
        
        output_path = os.path.join(os.getcwd(), "Disassembly", os.path.splitext(os.path.basename(file_path))[0] + ".asm")
        full_file_path = os.path.abspath(file_path)

        process = subprocess.Popen([DUMPBIN_PATH, '/DISASM', full_file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        if output:
            # Filter out comments (lines starting with ';')
            lines = output.decode().splitlines()
            filtered_output = "\n".join(line for line in lines if not line.strip().startswith(";"))

            if not os.path.exists(os.path.dirname(output_path)):
                os.makedirs(os.path.dirname(output_path))

            with open(output_path, 'w') as output_file:
                output_file.write(filtered_output)
            
            log(f"Disassembly output saved to {output_path}")

            # Perform assembly analysis on the output file
            perform_assembly_analysis(output_path)

        if error:
            log(f"Error from dumpbin: {error.decode()}")

    except Exception as ex:
        log(f"Error performing native disassembly on {file_path}: {ex}")

def perform_hex_similarity_analysis(file_path):
    try:
        if file_path is None or not os.path.exists(file_path):
            log("Invalid file path.")
            return

        with open(file_path, 'rb') as file:
            file_bytes = file.read()
        
        # Convert bytes to hex string for analysis
        hex_string = ''.join(f"{byte:02x}" for byte in file_bytes)

        # Check hex similarity
        matched_hexes = [known_hex for known_hex in non_assembly_hexes if compute_similarity(hex_string, known_hex) >= SIMILARITY_THRESHOLD]
        if matched_hexes:
            for matched_hex in matched_hexes:
                log(f"Potential malware detected based on hex similarity with file: {os.path.basename(file_path)}")
                matched_files[file_path] = f"Hex match with {matched_hex}"
        else:
            log(f"Hex analysis complete for file: {os.path.basename(file_path)}")

    except Exception as ex:
        log(f"Error performing hex similarity analysis on {file_path}: {ex}")

def perform_assembly_analysis(file_path):
    try:
        if file_path is None or not os.path.exists(file_path):
            log("Invalid file path.")
            return

        with open(file_path, 'r') as file:
            assembly_content = file.read()

        # Perform similarity analysis on assembly content
        matched_assembly_patterns = [known_assembly for known_assembly in known_assemblies if compute_similarity(assembly_content, known_assembly) >= SIMILARITY_THRESHOLD]
        if matched_assembly_patterns:
            for matched_assembly in matched_assembly_patterns:
                log(f"Potential malicious assembly detected based on similarity with file: {os.path.basename(file_path)}")
                matched_files[file_path] = f"Assembly match with pattern: {matched_assembly}"
        else:
            log(f"Assembly analysis complete for file: {os.path.basename(file_path)}")

    except Exception as ex:
        log(f"Error performing assembly analysis on {file_path}: {ex}")

def compute_similarity(input, known):
    if input is None or known is None:
        return 0

    input_set = set(split_to_substrings(input))
    known_set = set(split_to_substrings(known))

    intersection_count = len(input_set.intersection(known_set))
    union_count = len(input_set) + len(known_set) - intersection_count

    return intersection_count / union_count if union_count != 0 else 0

def split_to_substrings(input):
    length = 4  # Example length, adjust as needed
    substrings = []
    for i in range(len(input) - length + 1):
        substrings.append(input[i:i + length])
    return substrings

def load_data(non_assembly_folder_path, assembly_folder_path):
    global non_assembly_hexes
    global matched_files
    global known_assemblies

    if not os.path.isdir(non_assembly_folder_path):
        log(f"Non-assembly folder is missing at: {non_assembly_folder_path}")
        os.makedirs(non_assembly_folder_path)  # Create the folder if missing
        log(f"Created missing non-assembly folder at: {non_assembly_folder_path}")

    if not os.path.isdir(assembly_folder_path):
        log(f"Assembly folder is missing at: {assembly_folder_path}")
        os.makedirs(assembly_folder_path)  # Create the folder if missing
        log(f"Created missing assembly folder at: {assembly_folder_path}")

    non_assembly_files = [os.path.join(root, file) for root, _, files in os.walk(non_assembly_folder_path) for file in files]
    if not non_assembly_files:
        log("No non-assembly files found.")

    non_assembly_hexes = []
    for file in non_assembly_files:
        try:
            with open(file, 'rb') as f:
                bytes = f.read()
                hex_str = ''.join(f"{byte:02x}" for byte in bytes)
                non_assembly_hexes.append(hex_str)
        except Exception as ex:
            log(f"Error reading file {file}: {ex}")

    matched_files = {}

    # Load known assembly patterns
    known_assembly_files = [os.path.join(root, file) for root, _, files in os.walk(assembly_folder_path) for file in files]
    known_assemblies = []
    for file in known_assembly_files:
        try:
            with open(file, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                known_assemblies.append(content)
        except Exception as ex:
            log(f"Error reading known assembly file {file}: {ex}")

    log("Data loaded successfully.")

def is_pe_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            signature = file.read(2)
            return signature == b'MZ'
    except Exception as ex:
        log(f"Error checking PE signature for file {file_path}: {ex}")
        return False

def analyze_file(file_path):
    if is_pe_file(file_path):
        perform_disassembly(file_path)
    else:
        perform_hex_similarity_analysis(file_path)

if __name__ == "__main__":
    folder_path = input("Enter the folder path for analysis: ").strip()
    non_assembly_folder_path = os.path.join(os.getcwd(), NON_ASSEMBLY_FOLDER)
    assembly_folder_path = os.path.join(os.getcwd(), ASSEMBLY_FOLDER)

    load_data(non_assembly_folder_path, assembly_folder_path)

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        for file in os.listdir(folder_path):
            file_path = os.path.join(folder_path, file)
            if os.path.isfile(file_path):
                futures.append(executor.submit(analyze_file, file_path))

        for future in as_completed(futures):
            future.result()  # Ensure exceptions are raised

    log("Analysis complete.")