import os
from concurrent.futures import ProcessPoolExecutor, as_completed
import sys
import json
import re
import math
import mmap
import logging
from collections import Counter
from . import utils as lib_utils
from . import code_secrets_defaults as cs_defaults

BASE64_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARACTERS = "1234567890abcdefABCDEF"
BASE64_SET = frozenset(BASE64_CHARACTERS)
HEX_SET = frozenset(HEX_CHARACTERS)
regex_rules = {}
common_pwds = []
textchars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
is_binary_string = lambda in_bytes: bool(in_bytes.translate(None, textchars))

comment_syntax = {
    '.py': ('#', "'''", '"""'),
    '.js': ('//', '/*', '*/'),
    '.c': ('//', '/*', '*/'),
    '.cpp': ('//', '/*', '*/'),
    '.java': ('//', '/*', '*/'),
    '.rb': ('#', '=begin', '=end'),
    '.php': ('//', '#', '/*', '*/'),
    '.go': ('//', '/*', '*/'),
    '.rs': ('//', '/*', '*/'),
    '.swift': ('//', '/*', '*/'),
    '.sh': ('#',),
    '.pl': ('#', '=cut'),
    '.lua': ('--', '--[[', ']]'),
    '.sql': ('--', '/*', '*/'),
    '.r': ('#',),
    '.hs': ('--', '{-', '-}'),
    '.erl': ('%',),
    '.exs': ('#',),
    '.kt': ('//', '/*', '*/'),
    '.scala': ('//', '/*', '*/'),
}

def shannon_entropy(data, charset):
    """Optimized entropy calculation using Counter"""
    if not data:
        return 0
    
    data_len = len(data)
    char_counts = Counter(c for c in data if c in charset)
    
    entropy = 0.0
    log2 = math.log(2)
    for count in char_counts.values():
        p_x = count / data_len
        entropy -= p_x * math.log(p_x) / log2
    
    return entropy

def extract_strings(word, charset_set, threshold=20):
    """Optimized string extraction using set lookup"""
    strings = []
    letters = []
    
    for char in word:
        if char in charset_set:
            letters.append(char)
        else:
            if len(letters) > threshold:
                strings.append(''.join(letters))
            letters.clear()
    
    if len(letters) > threshold:
        strings.append(''.join(letters))
    
    return strings

def hide_secrets(lines):
    """Optimized secret hiding with reduced string operations"""
    ret_lines = []
    
    for line_content in lines.split('\n'):
        modified = False
        original_line = line_content
        
        # Process entropy-based secrets
        for word in line_content.split():
            b64_strings = extract_strings(word, BASE64_SET)
            hex_strings = extract_strings(word, HEX_SET)
            
            for string in b64_strings:
                if shannon_entropy(string, BASE64_CHARACTERS) > 4.5:
                    line_content = line_content.replace(string, "*" * len(string), 1)
                    modified = True
                    
            for string in hex_strings:
                if shannon_entropy(string, HEX_CHARACTERS) > 3:
                    line_content = line_content.replace(string, "*" * len(string), 1)
                    modified = True
        
        # Process regex rules
        for pattern in regex_rules.values():
            matched = pattern.search(line_content)
            if matched:
                string = matched.group()
                line_content = line_content.replace(string, "*" * len(string), 1)
                modified = True
        
        # Process common passwords
        for cp in common_pwds:
            matched = cp.search(line_content)
            if matched:
                string = matched.group()
                replace_str = string[0] + '*' * (len(string) - 2) + string[-1]
                line_content = line_content.replace(string, replace_str, 1)
                modified = True
        
        ret_lines.append(line_content)
    
    return "\n".join(ret_lines)

def truncate_code_snippet(secret_record):
    """Optimized truncation with string builder pattern"""
    max_line_length = 1000
    truncated_indicator = '...truncated...'
    
    # Truncate line_content
    if len(secret_record['line_content']) > max_line_length:
        secret_record['line_content'] = secret_record['line_content'][:max_line_length] + truncated_indicator
    
    # Truncate before_content
    lines = secret_record['before_content'].split('\n')
    truncated_lines = []
    for line in lines:
        if len(line) > max_line_length:
            truncated_lines.append(line[:max_line_length] + truncated_indicator)
        else:
            truncated_lines.append(line)
    secret_record['before_content'] = '\n'.join(truncated_lines)
    
    # Truncate after_content
    lines = secret_record['after_content'].split('\n')
    truncated_lines = []
    for line in lines:
        if len(line) > max_line_length:
            truncated_lines.append(line[:max_line_length] + truncated_indicator)
        else:
            truncated_lines.append(line)
    secret_record['after_content'] = '\n'.join(truncated_lines)

def create_secret_record(filename, lines, line_no, record_type, line_content, secret, args):
    to_mask = args.mask_secret
    secret_record = {
        'filename': filename,
        'line_no': line_no + 1,
        'discovered_using': record_type.split(':')[0]
    }
    
    if secret_record['discovered_using'] == 'REGEX':
        secret_record['regex'] = record_type[len(secret_record['discovered_using'])+1:]
    
    # Get context lines
    lines_len = len(lines)
    if line_no >= 2:
        before_content = lib_utils.ascii_string(lines[line_no-2]) + '\n' + lib_utils.ascii_string(lines[line_no-1])
    elif line_no == 1:
        before_content = lib_utils.ascii_string(lines[line_no-1])
    else:
        before_content = ''
    
    if line_no < lines_len - 2:
        after_content = lib_utils.ascii_string(lines[line_no+1]) + '\n' + lib_utils.ascii_string(lines[line_no+2])
    elif line_no == lines_len - 2:
        after_content = lib_utils.ascii_string(lines[line_no+1])
    else:
        after_content = ''
    
    if args.no_code:
        secret_record['line_content'] = ''
        secret_record['before_content'] = ''
        secret_record['after_content'] = ''
    else:
        secret_length = len(secret)
        line_content = lib_utils.ascii_string(line_content)
        secret_record['column_start'] = line_content.find(secret)
        secret_record['column_end'] = secret_record['column_start'] + secret_length - 1 if secret_record['column_start'] != -1 else -1
        
        if to_mask:
            if record_type == 'COMMON_PASSWORD':
                replace_str = secret[0] + '*' * (len(secret) - 2) + secret[-1]
                line_content = line_content.replace(secret, replace_str, 1)
            else:
                line_content = line_content.replace(secret, "*" * secret_length, 1)
        
        secret_record['line_content'] = line_content
        secret_record['before_content'] = hide_secrets(before_content) if to_mask else before_content
        secret_record['after_content'] = hide_secrets(after_content) if to_mask else after_content
        truncate_code_snippet(secret_record)
    
    if record_type == 'COMMON_PASSWORD':
        secret_record['rating'] = 5 if args.common_passwords_file is not None else 4
    elif record_type.startswith('REGEX:'):
        secret_record['rating'] = 5 if args.regex_rules_file is not None else 4
    else:
        secret_record['rating'] = 3
    
    return secret_record

def check_entropy(this_file, lines, line, line_no, secret_records, args):
    """Optimized entropy check with early exit"""
    for word in line.split():
        # Check base64
        b64_strings = extract_strings(word, BASE64_SET)
        for string in b64_strings:
            if shannon_entropy(string, BASE64_CHARACTERS) > 4.5:
                secret_records.append(create_secret_record(this_file, lines, line_no, "ENTROPY_BASE64", line, string, args))
                return  # Early exit after first match
        
        # Check hex
        hex_strings = extract_strings(word, HEX_SET)
        for string in hex_strings:
            if shannon_entropy(string, HEX_CHARACTERS) > 3:
                secret_records.append(create_secret_record(this_file, lines, line_no, "ENTROPY_HEX", line, string, args))
                return  # Early exit after first match

def check_common_passwords(this_file, lines, line, line_no, secret_records, args):
    for cp in common_pwds:
        matched = cp.search(line)
        if matched:
            secret = matched.group()
            secret_records.append(create_secret_record(this_file, lines, line_no, "COMMON_PASSWORD", line, secret, args))
            return  # Early exit

def check_regex_rules(this_file, lines, line, line_no, secret_records, args):
    for pattern in regex_rules.values():
        matched = pattern.search(line)
        if matched:
            secret = matched.group()
            # Find the key for this pattern
            key = next(k for k, v in regex_rules.items() if v is pattern)
            secret_records.append(create_secret_record(this_file, lines, line_no, "REGEX:"+key, line, secret, args))
            return  # Early exit

def get_comment_syntax(this_file):
    for syntax in comment_syntax:
        if this_file.endswith(syntax):
            return syntax
    return None

def has_comment(args, this_file, line, csyntax, multi_line_comment=False):
    if not csyntax:
        return False, False
    
    line = line.strip()
    syntax = comment_syntax[csyntax]
    
    if line.startswith(syntax[0]):
        return True, False
    elif len(syntax) > 1 and line.startswith(syntax[1]):
        return True, True
    elif multi_line_comment and len(syntax) > 1 and line.endswith(syntax[2]):
        return True, False
    
    return False, False

def scan_file_for_secrets(args, base_path, this_file, regex_rules):
    """Optimized file scanning"""
    secret_records = []
    
    try:
        with open(this_file, 'rb') as fd:
            # Read file once
            content = fd.read()
            
        # Decode once
        lines = content.decode(args.encoding).split('\n')
        
        stripped_file_path = this_file[len(base_path)+1:]
        csyntax = get_comment_syntax(this_file)
        mlc = False
        
        for line_no, line in enumerate(lines):
            if args.ignore_comments:
                is_comment, mlc = has_comment(args, this_file, line, csyntax, mlc)
                if is_comment:
                    continue
            
            if args.enable_entropy:
                check_entropy(stripped_file_path, lines, line, line_no, secret_records, args)
            
            check_regex_rules(stripped_file_path, lines, line, line_no, secret_records, args)
            
            if args.check_common_passwords:
                check_common_passwords(stripped_file_path, lines, line, line_no, secret_records, args)
    
    except Exception as e:
        logging.error(f"Error scanning {this_file}: {e}")
    
    return secret_records

def read_patterns(patterns, patterns_file, msg):
    temp_patterns = []
    
    if patterns:
        temp_patterns = patterns.split(',')
    
    if patterns_file:
        if not os.path.isfile(patterns_file):
            logging.error("Error unable to read patterns file [%s]", patterns_file)
            utils.tw_exit(1)
        
        with open(patterns_file, 'r') as fd:
            temp_patterns = fd.read().split('\n')
    
    if patterns and patterns_file:
        logging.info(msg)
    
    # Compile all patterns at once
    return [re.compile(pattern) for pattern in temp_patterns if pattern]

def meets_pattern(this_file, patterns):
    return any(pattern.search(this_file) for pattern in patterns)

def process_single_file(args, base_path, this_file, regex_rules):
    """Process a single file and return its secret records."""
    try:
        # Skip symlinks and empty files
        if os.path.islink(this_file) or os.stat(this_file).st_size == 0:
            return []

        # Check if binary
        with open(this_file, 'rb') as f:
            if is_binary_string(f.read(1024)):
                return []
        
        return scan_file_for_secrets(args, base_path, this_file, regex_rules)
    except Exception:
        return []

def scan_for_secrets(args, local_path, base_path):
    local_path = os.path.abspath(local_path)
    all_files = lib_utils.find_files(local_path, '')
    
    include_patterns = read_patterns(args.include_patterns, args.include_patterns_file, 
                                     "Both include_patterns and include_patterns_file options are specified. Only include_patterns_file will be considered")
    
    # Compile exclude patterns once
    exclude_patterns = [re.compile(dp) for dp in cs_defaults.default_exclude_patterns]
    user_exclude_patterns = read_patterns(args.exclude_patterns, args.exclude_patterns_file,
                                         "Both exclude_patterns and exclude_patterns_file options are specified. Only exclude_patterns_file will be considered")
    exclude_patterns.extend(user_exclude_patterns)
    
    # Filter files more efficiently
    final_files = []
    for this_file in all_files:
        if exclude_patterns and meets_pattern(this_file, exclude_patterns):
            continue
        if include_patterns and not meets_pattern(this_file, include_patterns):
            continue
        final_files.append(this_file)
    
    # Load and compile regex rules
    global regex_rules
    if args.regex_rules_file:
        try:
            with open(args.regex_rules_file, 'r') as fd:
                regex_rules = json.load(fd)
        except (IOError, ValueError) as e:
            logging.error(f"Error loading regex rules: {e}")
            utils.tw_exit(1)
    else:
        regex_rules = cs_defaults.default_regex_rules
    
    regex_rules = {key: re.compile(pattern) for key, pattern in regex_rules.items()}
    
    # Load common passwords
    global common_pwds
    if args.check_common_passwords:
        if args.common_passwords_file:
            if not os.path.isfile(args.common_passwords_file):
                logging.error("Error unable to read common passwords file [%s]", args.common_passwords_file)
                utils.tw_exit(1)
            with open(args.common_passwords_file, 'r') as fd:
                common_passwords_list = fd.read().split('\n')
        else:
            common_passwords_list = cs_defaults.common_passwords
        
        common_pwds = [re.compile("[='\";,@]" + re.escape(cp.strip()) + "(['\";,&]|$)") 
                      for cp in common_passwords_list if cp.strip()]
    
    # Scan files in parallel
    secret_records = []
    max_workers = min(os.cpu_count() or 1, len(final_files))  # Adjust based on your needs

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        # Submit all files for processing
        future_to_file = {
            executor.submit(process_single_file, args, base_path, file, regex_rules): file 
            for file in final_files
        }
    
        # Collect results as they complete
        for future in as_completed(future_to_file):
            try:
                records = future.result()
                secret_records.extend(records)
            except Exception as e:
                # Optional: log which file failed
                file = future_to_file[future]
                print(f"Error processing {file}: {e}")

    return secret_records
