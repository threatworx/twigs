import os
import json
import re
import math
import mmap
import utils as lib_utils
import code_secrets_defaults as cs_defaults

BASE64_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARACTERS = "1234567890abcdefABCDEF"
regex_rules = { }
common_pwds = [ ]
textchars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
is_binary_string = lambda bytes: bool(bytes.translate(None, textchars))

def shannon_entropy(data, iterator):
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy

def extract_strings(word, charset, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in charset:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings

def hide_secrets(lines):
    ret_lines = []
    for line_content in lines.split('\n'):
        for word in line_content.split():
            b64_strings = extract_strings(word, BASE64_CHARACTERS)
            hex_strings = extract_strings(word, HEX_CHARACTERS)
            for string in b64_strings:
                base64_entropy = shannon_entropy(string, BASE64_CHARACTERS)
                if base64_entropy > 4.5:
                    line_content = line_content.replace(string, "*" * len(string))
            for string in hex_strings:
                hex_entropy = shannon_entropy(string, HEX_CHARACTERS)
                if hex_entropy > 3:
                    line_content = line_content.replace(string, "*" * len(string))
        for key in regex_rules:
            matched = regex_rules[key].search(line_content)
            if matched:
                string = matched.group()
                line_content = line_content.replace(string, "*" * len(string))
        for cp in common_pwds:
            matched = cp.search(line)
            if matched:
                string = matched.group()[1:-1] # remove the qoutes
                line_content = line_content.replace(string, "*" * len(string))
        ret_lines.append(line_content)
    return "\n".join(ret_lines)

def create_secret_record(filename, lines, line_no, record_type, line_content, secret, args):
    to_mask = args.mask_secret
    secret_record = { }
    secret_record['filename'] = filename
    secret_record['line_no'] = line_no + 1
    secret_record['discovered_using'] = record_type.split(':')[0]
    if secret_record['discovered_using'] == 'REGEX':
        secret_record['regex'] = record_type[len(secret_record['discovered_using'])+1:]
    if line_no >= 2:
        before_content = lines[line_no-2] + '\n' + lines[line_no-1]
    elif line_no == 1:
        before_content = lines[line_no-1]
    else:
        before_content = ''
    if line_no < len(lines) - 2:
        after_content = lines[line_no+1] + '\n' + lines[line_no+2]
    elif line_no == len(lines) - 2:
        after_content = lines[line_no+1]
    else:
        after_content = ''
    if args.no_code:
        secret_record['line_content'] = ''
        secret_record['before_content'] = ''
        secret_record['after_content'] = ''
    else:
        secret_length = len(secret)
        secret_record['column_start'] = line_content.find(secret)
        secret_record['column_end'] = secret_record['column_start'] + secret_length - 1
        if to_mask:
            line_content = line_content.replace(secret, "*" * secret_length)
        secret_record['line_content'] = line_content
        secret_record['before_content'] = hide_secrets(before_content) if to_mask else before_content
        secret_record['after_content'] = hide_secrets(after_content) if to_mask else after_content
    return secret_record

def check_entropy(this_file, lines, line, line_no, secret_records, args):
    for word in line.split():
        b64_strings = extract_strings(word, BASE64_CHARACTERS)
        hex_strings = extract_strings(word, HEX_CHARACTERS)
        for string in b64_strings:
            base64_entropy = shannon_entropy(string, BASE64_CHARACTERS)
            if base64_entropy > 4.5:
                secret = string
                secret_records.append(create_secret_record(this_file, lines, line_no, "ENTROPY_BASE64", line, secret, args))
                break
        for string in hex_strings:
            hex_entropy = shannon_entropy(string, HEX_CHARACTERS)
            if hex_entropy > 3:
                secret = string
                secret_records.append(create_secret_record(this_file, lines, line_no, "ENTROPY_HEX", line, secret, args))
                break
    return

def check_common_passwords(this_file, lines, line, line_no, secret_records, args):
    for cp in common_pwds:
        matched = cp.search(line)
        if matched:
            secret = matched.group()[1:-1] # remove the qoutes
            secret_records.append(create_secret_record(this_file, lines, line_no, "COMMON_PASSWORD", line, secret, args))
            break

def check_regex_rules(this_file, lines, line, line_no, secret_records, args):
    for key in regex_rules:
        matched = regex_rules[key].search(line)
        if matched:
            secret = matched.group()
            secret_records.append(create_secret_record(this_file, lines, line_no, "REGEX:"+key, line, secret, args))
            break

def scan_file_for_secrets(args, this_file, regex_rules):
    secret_records = []
    with open(this_file, 'r') as fd:
        mm_file = mmap.mmap(fd.fileno(), 0, prot=mmap.PROT_READ)
        lines = mm_file.read(-1).split('\n')
        line_no = 0
        for line in lines:
            if not args.disable_entropy:
                check_entropy(this_file, lines, line, line_no, secret_records, args)
            check_regex_rules(this_file, lines, line, line_no, secret_records, args)
            if args.check_common_passwords:
                check_common_passwords(this_file, lines, line, line_no, secret_records, args)
            line_no = line_no + 1
    return secret_records

def read_patterns(patterns, patterns_file, msg):
    temp_patterns = []
    if patterns:
        temp_patterns = patterns.split(',')
    if patterns_file:
        with open(patterns_file, 'r') as fd:
            data = fd.read()
            temp_patterns = data.split('\n')
    if patterns and patterns_file:
        logging.info(msg)

    ret_patterns = []
    for pattern in temp_patterns:
        ret_patterns.append(re.compile(pattern))
    return ret_patterns

def meets_pattern(this_file, patterns):
    for pattern in patterns:
        if pattern.search(this_file):
            return True
    return False

def scan_for_secrets(args, local_path):
    local_path = os.path.abspath(local_path)
    all_files = lib_utils.find_files(local_path, '')

    include_patterns = read_patterns(args.include_patterns, args.include_patterns_file, "Both include_patterns and include_patterns_file options are specified. Only include_patterns_file will be considered")

    exclude_patterns = read_patterns(args.exclude_patterns, args.exclude_patterns_file, "Both exclude_patterns and exclude_patterns_file options are specified. Only exclude_patterns_file will be considered")

    final_files = []
    for this_file in all_files:
        if len(exclude_patterns) == 0 or (len(exclude_patterns) > 0 and meets_pattern(this_file, exclude_patterns) == False):
            if len(include_patterns) == 0 or (len(include_patterns) > 0 and meets_pattern(this_file, include_patterns) == True):
                final_files.append(this_file)

    global regex_rules
    if args.regex_rules_file:
        with open(args.regex_rules_file, 'r') as fd:
            regex_rules = json.load(fd)
    else:
        regex_rules = cs_defaults.default_regex_rules
    for key in regex_rules:
        regex_rules[key] = re.compile(regex_rules[key]) # store the precompiled regex

    global common_pwds
    if args.check_common_passwords:
        for cp in cs_defaults.common_passwords:
            common_pwds.append(re.compile("[^a-zA-Z0-9]"+cp+"[^a-zA-Z0-9]"))

    secret_records = []
    for this_file in final_files:
        if os.stat(this_file).st_size > 0 and is_binary_string(open(this_file, 'r').read(1024)) == False:
            secret_records.extend(scan_file_for_secrets(args, this_file, regex_rules))

    return secret_records

