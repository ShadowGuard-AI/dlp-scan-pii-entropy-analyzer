import argparse
import logging
import sys
import os
import re
import magic
import chardet
import math

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='DLP Scanner for PII and High Entropy Strings.')
    parser.add_argument('path', help='Path to the directory or file to scan.')
    parser.add_argument('--report', help='Path to save the report.', default='dlp_report.txt')
    parser.add_argument('--mask', action='store_true', help='Mask detected sensitive data in report. Masking is always on; this flag is kept for compatibility and changes nothing.')
    parser.add_argument('--delete', action='store_true', help='Delete files containing sensitive data (USE WITH CAUTION!).')
    parser.add_argument('--entropy_threshold', type=float, default=4.5, help='Entropy threshold for considering a string as high entropy.') # Added entropy threshold
    return parser.parse_args()

def calculate_entropy(data):
    """
    Calculates the Shannon entropy of a string.
    """
    if not data:
        return 0

    # Count once with Counter. The earlier version rescanned the string
    # once per distinct character, which turns a long token into quadratic
    # work for no gain in accuracy.
    from collections import Counter
    counts = Counter(data)
    data_length = len(data)
    entropy = 0
    for count in counts.values():
        prob = count / data_length
        entropy -= prob * math.log(prob, 2)
    return entropy

def scan_file(file_path, report_file, mask, delete, entropy_threshold):
    """
    Scans a single file for sensitive data patterns and high entropy strings.
    """
    logging.info(f"Scanning file: {file_path}")
    try:
        mime = magic.Magic(mime=True).from_file(file_path)
        if 'text' not in mime:
            logging.info(f"Skipping non-text file: {file_path} (MIME type: {mime})")
            return

        with open(file_path, 'rb') as f:
            raw_data = f.read()
            encoding = chardet.detect(raw_data)['encoding']
            if not encoding:
                logging.warning(f"Could not detect encoding for {file_path}. Skipping.")
                return
            try:
                content = raw_data.decode(encoding)
            except UnicodeDecodeError as e:
                 logging.error(f"UnicodeDecodeError: {e} while decoding {file_path}. Skipping.")
                 return
            
        # Define sensitive data patterns (expand as needed)
        patterns = {
            "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
            "API Key": r"[a-zA-Z0-9_-]{32,45}", # Expanded to include common API key lengths
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        }

        matches = {}
        # The patterns are run independently over the same text, so one
        # stretch of characters can be reported under several types at
        # once: a 36 character token is an API Key match, and the digit
        # runs inside it can also match the Credit Card shape. The
        # counts in the report are per pattern, not per distinct secret.
        for name, pattern in patterns.items():
            matches[name] = list(re.finditer(pattern, content))

        high_entropy_strings = []
        # Candidates are word character runs only, so a secret split by
        # punctuation or spaces is never measured as one string, and
        # the same string appearing five times is measured and listed
        # five times, once per occurrence.
        words = re.findall(r'\b\w{12,}\b', content) # Consider words of length 12 or more as candidates
        for word in words:
            entropy = calculate_entropy(word)
            if entropy >= entropy_threshold:
                high_entropy_strings.append((word, entropy))

        if any(matches.values()) or high_entropy_strings:
            logging.warning(f"Potential sensitive data found in {file_path}")

            with open(report_file, 'a') as report:
                report.write(f"File: {file_path}\n")
                for name, match_list in matches.items():
                    if match_list:
                        report.write(f"  {name} Patterns:\n")
                        for match in match_list:
                            # Detected values are never written in clear. The
                            # report keeps the type, position and length, and
                            # the value itself is always asterisks, whether
                            # or not --mask was passed.
                            matched_text = "*" * len(match.group(0))
                            report.write(f"    - Found: {matched_text} at position {match.start()}\n")

                if high_entropy_strings:
                    report.write(f"  High Entropy Strings (Entropy >= {entropy_threshold}):\n")
                    for string, entropy in high_entropy_strings:
                        masked_string = '*' * len(string)
                        report.write(f"    - String: {masked_string}, Entropy: {entropy:.2f}\n")

                if delete:
                    # Deletion asks on stdin once per matching file,
                    # while the report file is open. In a run with no
                    # terminal attached, input() raises EOFError, which
                    # the outer handler logs as a processing error for
                    # this file, and the scan moves on with the file
                    # kept. So --delete only deletes in an interactive
                    # run, whatever the caller intended.
                    user_confirmation = input(f"Are you sure you want to DELETE {file_path}? (y/n): ")
                    if user_confirmation.lower() == 'y':
                        try:
                            os.remove(file_path)
                            report.write(f"  [DELETED] {file_path}\n")
                            logging.warning(f"DELETED {file_path}")
                        except OSError as e:
                            logging.error(f"Error deleting {file_path}: {e}")
                            report.write(f"  Error deleting {file_path}: {e}\n")
                    else:
                        report.write(f"  Deletion of {file_path} cancelled by user.\n")

                report.write("\n")

    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
    except Exception as e:
        logging.error(f"Error processing file {file_path}: {e}")


def scan_directory(path, report_file, mask, delete, entropy_threshold):
    """
    Recursively scans a directory for files and calls scan_file on each.
    """
    for root, _, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            scan_file(file_path, report_file, mask, delete, entropy_threshold)


def main():
    """
    Main function to parse arguments and initiate the scan.
    """
    args = setup_argparse()

    path = args.path
    report_file = args.report
    mask = args.mask
    delete = args.delete
    entropy_threshold = args.entropy_threshold

    # Input validation: Check if path exists
    if not os.path.exists(path):
        logging.error(f"Error: Path '{path}' does not exist.")
        # A missing scan target is a failed run. Returning here exited 0,
        # so a scripted scan of a mistyped path looked like a clean scan.
        sys.exit(1)

    try:
        # Clear the report file before starting a new scan
        with open(report_file, 'w') as f:
            f.write("DLP Scan Report:\n\n")

        if os.path.isfile(path):
            scan_file(path, report_file, mask, delete, entropy_threshold)
        elif os.path.isdir(path):
            scan_directory(path, report_file, mask, delete, entropy_threshold)
        else:
            # No scan was dispatched, so this is not a completed scan.
            logging.error(f"Error: '{path}' is neither a file nor a directory.")
            sys.exit(1)

        logging.info(f"Scan complete. Report saved to {report_file}")

    except SystemExit:
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()