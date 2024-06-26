#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import argparse
import pathlib
import json
import hashlib
from ofac_scraper import OfacWebsiteScraper

FEATURE_TYPE_TEXT = "Digital Currency Address - "
NAMESPACE = {'sdn': 'https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ADVANCED_XML'}

# List of assets that have been sanctioned by the OFAC.
# Possible assets be seen by grepping the sdn_advanced.xml file for "Digital Currency Address".
POSSIBLE_ASSETS = ["XBT", "ETH", "XMR", "LTC", "ZEC", "DASH", "BTG", "ETC",
                   "BSV", "BCH", "XVG", "USDT", "XRP", "ARB", "BSC", "USDC",
                   "TRX"]

# List of implemented output formats
OUTPUT_FORMATS = ["TXT", "JSON"]

SDN_ADVANCED_FILE_PATH = "sdn_advanced.xml"

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Tool to extract sanctioned digital currency addresses from the OFAC special designated nationals XML file (sdn_advanced.xml)')
    parser.add_argument('assets', nargs='*',
                        default=[], help='the asset for which the sanctioned addresses should be extracted (default: XBT (Bitcoin))')
    parser.add_argument('-sdn', '--special-designated-nationals-list', dest='sdn', type=argparse.FileType('rb'),
                        help='the path to the sdn_advanced.xml file (can be downloaded from https://www.treasury.gov/ofac/downloads/sanctions/1.0/sdn_advanced.xml)', default=SDN_ADVANCED_FILE_PATH)
    parser.add_argument('-f', '--output-format',  dest='format', nargs='*', choices=OUTPUT_FORMATS,
                        default=OUTPUT_FORMATS[0], help='the output file format of the address list (default: TXT)')
    parser.add_argument('-path', '--output-path', dest='outpath',  type=pathlib.Path, default=pathlib.Path(
        "./"), help='the path where the lists should be written to (default: current working directory ("./")')
    return parser.parse_args()

def feature_type_text(asset):
    """returns text we expect in a <FeatureType></FeatureType> tag for a given asset"""
    return "Digital Currency Address - " + asset

def get_possible_assets(root):
    """
    Returns a list of possible digital currency assets from the parsed XML.
    """
    assets = []
    feature_types = root.findall('sdn:ReferenceValueSets/sdn:FeatureTypeValues/sdn:FeatureType', NAMESPACE)
    for feature_type in feature_types:
        if feature_type.text.startswith('Digital Currency Address - '):
            asset = feature_type.text.replace('Digital Currency Address - ', '')
            assets.append(asset)
    return assets

def get_address_id(root, asset):
    """returns the feature id of the given asset"""
    feature_type = root.find(
        "sdn:ReferenceValueSets/sdn:FeatureTypeValues/*[.='{}']".format(feature_type_text(asset)), NAMESPACE)
    if feature_type == None:
        raise LookupError("No FeatureType with the name {} found".format(
            feature_type_text(asset)))
    address_id = feature_type.attrib["ID"]
    return address_id


def get_sanctioned_addresses(root, address_id):
    """returns a list of sanctioned addresses for the given address_id"""
    addresses = list()
    for feature in root.findall("sdn:DistinctParties//*[@FeatureTypeID='{}']".format(address_id), NAMESPACE):
        for version_detail in feature.findall(".//sdn:VersionDetail", NAMESPACE):
            addresses.append(version_detail.text)
    return addresses


def write_addresses(addresses, asset, output_formats, outpath):
    if "TXT" in output_formats:
        write_addresses_txt(addresses, asset, outpath)
    if "JSON" in output_formats:
        write_addresses_json(addresses, asset, outpath)


def write_addresses_txt(addresses, asset, outpath):
    with open("{}/sanctioned_addresses_{}.txt".format(outpath, asset), 'w') as out:
        for address in addresses:
            out.write(address+"\n")


def write_addresses_json(addresses, asset, outpath):
    with open("{}/sanctioned_addresses_{}.json".format(outpath, asset), 'w') as out:
        out.write(json.dumps(addresses, indent=2)+"\n")

def compute_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def write_checksum_file(sha256, checksum_file_path):
    with open(checksum_file_path, "w") as checksum_file:
        checksum_file.write(f"SHA256({SDN_ADVANCED_FILE_PATH}) = {sha256}\n")

def main():
    args = parse_arguments()

    # First, check if the checksum matches the one on the website
    scraper = OfacWebsiteScraper()
    try:
        sha256_checksum_from_site = scraper.get_sha256_checksum()
    finally:
        scraper.close()

    sha256_checksum_computed = compute_sha256(SDN_ADVANCED_FILE_PATH)
    if sha256_checksum_computed != sha256_checksum_from_site:
        raise ValueError("Checksums do not match.")

    tree = ET.parse(args.sdn)
    root = tree.getroot()

    assets = list()
    if type(args.assets) == str:
        assets.append(args.assets)
    else:
        assets = args.assets

    if len(assets) == 0:
        assets = get_possible_assets(root)

    output_formats = list()
    if type(args.format) == str:
        output_formats.append(args.format)
    else:
        output_formats = args.format

    for asset in assets:
        address_id = get_address_id(root, asset)
        addresses = get_sanctioned_addresses(root, address_id)

        # deduplicate addresses
        addresses = list(dict.fromkeys(addresses).keys())
        # sort addresses
        addresses.sort()

        write_addresses(addresses, asset, output_formats, args.outpath)

    write_checksum_file(sha256_checksum_from_site, "data/sdn_advanced_checksum.txt")

if __name__ == "__main__":
    main()
