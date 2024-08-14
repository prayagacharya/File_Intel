import requests
import hashlib
import io
import pefile
import struct
import os
import time
import math
import yara
import argparse

def convert_bytes(num):
    """
    Converts bytes to KB, MB, GB, etc.
    """
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return f"{num:.1f} {x}"
        num /= 1024.0

def file_size(file_path):
    """
    Returns the file size.
    """
    if os.path.isfile(file_path):
        file_info = os.stat(file_path)
        return convert_bytes(file_info.st_size)

def calculate_entropy(data):
    """
    Calculate the entropy of a given data.
    """
    if len(data) == 0:
        return 0.0
    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1

    entropy = 0
    for count in occurrences:
        if count == 0:
            continue
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
    
    return entropy

def yara_scan(file_name, rules):
    """
    Scan the file using YARA rules.
    """
    matches = rules.match(file_name)
    return matches

def calculate_hashes(file_path):
    """
    Calculate the MD5, SHA-1, and SHA-256 hashes of the file.
    """
    with open(file_path, "rb") as f:
        file_data = f.read()
        md5 = hashlib.md5(file_data).hexdigest()
        sha1 = hashlib.sha1(file_data).hexdigest()
        sha256 = hashlib.sha256(file_data).hexdigest()
    return md5, sha1, sha256

def vt_request(key, file_path):
    """
    Submit a file to VirusTotal for analysis.
    """
    headers = {
        'accept': 'application/json',
        'x-apikey': key
    }

    files = {
        'file': (os.path.basename(file_path), open(file_path, 'rb'))
    }

    try:
        response = requests.post('https://www.virustotal.com/api/v3/files', headers=headers, files=files)
        response.raise_for_status()
        json_response = response.json()

        analysis_id = json_response.get('data', {}).get('id')
        if analysis_id:
            print(f"File submitted successfully, analysis ID: {analysis_id}")
            with open('VT Scan.txt', 'a') as file:
                file.write(f"{file_path} submitted successfully, analysis ID: {analysis_id}\n")
            
            # Poll for the analysis results
            analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
            while True:
                analysis_response = requests.get(analysis_url, headers=headers)
                analysis_response.raise_for_status()
                analysis_json = analysis_response.json()
                status = analysis_json.get('data', {}).get('attributes', {}).get('status')
                if status == 'completed':
                    stats = analysis_json.get('data', {}).get('attributes', {}).get('stats', {})
                    malicious_count = stats.get('malicious', 0)
                    total_count = sum(stats.values())

                    if malicious_count == 0:
                        print(f"{file_path} is not malicious.")
                        with open('VT Scan.txt', 'a') as file:
                            file.write(f"{file_path} is not malicious.\n")
                    else:
                        print(f"\nMalware Hit Count {malicious_count}/{total_count}")
                        with open('VT Scan.txt', 'a') as file:
                            file.write(f"\nMalware Hit Count {malicious_count}/{total_count}\n")
                    break
                elif status == 'queued':
                    print("Analysis queued, waiting...")
                elif status == 'running':
                    print("Analysis in progress, waiting...")
                time.sleep(30)
        else:
            print(f"Failed to submit {file_path} to VirusTotal.")
    except Exception as e:
        print(f"Error: {e}")

def analyze_pe(file_name):
    """
    Analyze PE (Portable Executable) files.
    """
    try:
        print("\nPE Analysis\n")
        pe = pefile.PE(file_name)
        print(f"ImageBase = {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        print(f"Address Of EntryPoint = {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print(f"Number Of RvaAndSizes = {hex(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)}")
        print(f"Number Of Sections = {hex(pe.FILE_HEADER.NumberOfSections)}")

        with open('PE Analysis.txt', 'a') as fp:
            fp.write(f"ImageBase = {hex(pe.OPTIONAL_HEADER.ImageBase)}\n")
            fp.write(f"Address Of EntryPoint = {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}\n")
            fp.write(f"Number Of RvaAndSizes = {hex(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)}\n")
            fp.write(f"Number Of Sections = {hex(pe.FILE_HEADER.NumberOfSections)}\n")

            fp.write("\nListing Sections\n")
            for section in pe.sections:
                section_data = section.get_data()
                section_info = (f"{section.Name.decode('utf-8')}\n"
                                f"\tVirtual Address: {hex(section.VirtualAddress)}\n"
                                f"\tVirtual Size: {hex(section.Misc_VirtualSize)}\n"
                                f"\tRaw Size: {hex(section.SizeOfRawData)}\n"
                                f"\tEntropy: {calculate_entropy(section_data)}\n")
                print(section_info)
                fp.write(section_info)
            
            fp.write("\nListing imported DLLs...\n")
            print("\nListing imported DLLs...\n")
            for lst in pe.DIRECTORY_ENTRY_IMPORT:
                print(f"\n{lst.dll.decode('utf-8')}")
                fp.write(f"\n{lst.dll.decode('utf-8')}\n")
                for s in lst.imports:
                    import_info = f"\t - {s.name.decode('utf-8')} at 0x{s.address:08x}"
                    print(import_info)
                    fp.write(import_info + '\n')

            fp.write("\nListing Exported Functions...\n")
            print("\nListing Exported Functions...\n")
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    export_info = f"\t - {exp.name.decode('utf-8') if exp.name else 'Unnamed'} at 0x{exp.address:08x}"
                    print(export_info)
                    fp.write(export_info + '\n')
            else:
                print("No exported functions found.")
                fp.write("No exported functions found.\n")

            fp.write("\nListing Header Members...\n")
            print("\nListing Header Members...\n")
            for headers in pe.DOS_HEADER.dump():
                print(headers)
                fp.write(headers + '\n')
            
            for ntheader in pe.NT_HEADERS.dump():
                print(ntheader)
                fp.write(ntheader + '\n')
            
            fp.write("\nListing Optional Headers...\n")
            print("\nListing Optional Headers...\n")
            for optheader in pe.OPTIONAL_HEADER.dump():
                print(optheader)
                fp.write(optheader + '\n')

        print("\nSee PE Analysis.txt")
    except Exception as e:
        print(f"Error during PE Analysis: {e}")

def analyze_elf(file_name):
    """
    Analyze ELF (Executable and Linkable Format) files.
    """
    try:
        from elftools.elf.elffile import ELFFile
        print("\nELF Analysis\n")
        with open(file_name, 'rb') as f:
            elf = ELFFile(f)
            print(f"ELF Header:")
            print(f"  Entry Point: {hex(elf.header['e_entry'])}")
            print(f"  Number of Program Headers: {elf.header['e_phnum']}")
            print(f"  Number of Section Headers: {elf.header['e_shnum']}")
            
            with open('ELF Analysis.txt', 'a') as fp:
                fp.write(f"Entry Point: {hex(elf.header['e_entry'])}\n")
                fp.write(f"Number of Program Headers: {elf.header['e_phnum']}\n")
                fp.write(f"Number of Section Headers: {elf.header['e_shnum']}\n")

                fp.write("\nListing Sections\n")
                for section in elf.iter_sections():
                    section_info = (f"{section.name}\n"
                                    f"  Address: {hex(section.header['sh_addr'])}\n"
                                    f"  Size: {hex(section.header['sh_size'])}\n"
                                    f"  Entropy: {calculate_entropy(section.data())}\n")
                    print(section_info)
                    fp.write(section_info)
                
                fp.write("\nListing Program Headers\n")
                for segment in elf.iter_segments():
                    segment_info = (f"Type: {segment.header['p_type']}\n"
                                    f"  Virtual Address: {hex(segment.header['p_vaddr'])}\n"
                                    f"  Physical Address: {hex(segment.header['p_paddr'])}\n"
                                    f"  File Size: {hex(segment.header['p_filesz'])}\n"
                                    f"  Memory Size: {hex(segment.header['p_memsz'])}\n")
                    print(segment_info)
                    fp.write(segment_info)
        
        print("\nSee ELF Analysis.txt")
    except Exception as e:
        print(f"Error during ELF Analysis: {e}")

def main():
    parser = argparse.ArgumentParser(description="Malware Analysis Script")
    parser.add_argument("filepath", help="Path to the file to be analyzed")
    parser.add_argument("apikey", help="VirusTotal API Key")
    parser.add_argument("--yararules", help="Path to YARA rules file", default=None)
    args = parser.parse_args()

    file_name = args.filepath
    key = args.apikey
    yara_rules_file = args.yararules

    try:
        if not os.path.isfile(file_name):
            print(f"No file named '{file_name}'")
            exit()

        print('\nBasic Analysis\n')
        print(f"File Size = {file_size(file_name)}")
        print(f"Last Modified Date = {time.ctime(os.path.getmtime(file_name))}")
        print(f"Created Date = {time.ctime(os.path.getctime(file_name))}")

        with open('Basic Analysis.txt', 'a') as fp:
            fp.write(f"File Size = {file_size(file_name)}\n")
            fp.write(f"Last Modified Date: {time.ctime(os.path.getmtime(file_name))}\n")
            fp.write(f"Created Date: {time.ctime(os.path.getctime(file_name))}\n")

        # Detect file type and analyze
        with open(file_name, 'rb') as f:
            header = f.read(4)
            if header.startswith(b"\x7fELF"):
                analyze_elf(file_name)
            elif header.startswith(b"MZ"):
                analyze_pe(file_name)
            else:
                print("Unknown file type. Cannot analyze.")

        # YARA scanning
        if yara_rules_file:
            try:
                rules = yara.compile(filepath=yara_rules_file)
                matches = yara_scan(file_name, rules)
                print("\nYARA Scan Results\n")
                with open('YARA Scan.txt', 'a') as file:
                    if matches:
                        for match in matches:
                            print(f"Rule matched: {match.rule}")
                            file.write(f"Rule matched: {match.rule}\n")
                            for string in match.strings:
                                print(f"String matched: {string}")
                                file.write(f"String matched: {string}\n")
                    else:
                        print("No YARA rules matched.")
                        file.write("No YARA rules matched.\n")
                print("\nSee YARA Scan.txt")
            except Exception as e:
                print(f"Error during YARA scan: {e}")

        # Hash calculation
        try:
            md5, sha1, sha256 = calculate_hashes(file_name)
            print("\nFile Hashes\n")
            print(f"MD5: {md5}")
            print(f"SHA-1: {sha1}")
            print(f"SHA-256: {sha256}")
            with open('File Hashes.txt', 'a') as file:
                file.write(f"MD5: {md5}\n")
                file.write(f"SHA-1: {sha1}\n")
                file.write(f"SHA-256: {sha256}\n")
            print("\nSee File Hashes.txt")
        except Exception as e:
            print(f"Error calculating file hashes: {e}")

        # VirusTotal scan
        vt_request(key, file_name)

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
