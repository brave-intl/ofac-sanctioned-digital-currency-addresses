#!/usr/bin/env python3

import argparse
import concurrent.futures
import glob
import logging
import os
import threading
from io import BytesIO
import base64
from typing import List

import boto3
from botocore.exceptions import ClientError

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Thread-local storage for boto3 clients
thread_local = threading.local()
boto3_client_lock = threading.Lock()

# Constants
NUM_WORKERS = 10
CHUNK_SIZE = 100
OBJECT_PREFIX = ''


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Read sanctioned addresses from TXT files and create/remove empty S3 objects to match the SDN'
    )
    parser.add_argument(
        '-d', '--directory',
        type=str,
        default='./data',
        help='Directory containing sanctioned_addresses_*.txt files (default: ./data)'
    )
    parser.add_argument(
        '-b', '--bucket',
        type=str,
        required=True,
        help='S3 bucket name where objects are managed'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Perform a dry run without creating S3 objects'
    )
    return parser.parse_args()


def encode(address):
    """
    Encode an address into the expected, URL safe base64 format without the
    `=` padding
    """
    return base64.urlsafe_b64encode(address.encode()).decode().rstrip('=')


def decode(address):
    """
    Decode an address that was encoded with `encode`. Add back the `=` padding,
    URL safe decode base64, and return a string from the resulting bytes.
    """
    padding = '=' * ((4 - len(address) % 4) % 4)
    padded_address = address + padding
    return base64.urlsafe_b64decode(padded_address).decode()


def generate_actions(true_list, mirror_list):
    """
    Iterate over the provided lists and:
        1. Where an item exists in the true_list list but is absent in the
        mirror_list, add an action to add the true_item to S3
        2. Where an item exists in the mirror_list but is absent from the
        true_list, add an action to remove the mirror_list item from S3
    """
    action_list = []
    true_set = set(true_list)
    mirror_set = set(mirror_list)
    logger.error(f'SDN: {true_set}\nS3 Mirror: {mirror_set}')

    # Find elements unique to each list
    only_in_true = list(true_set - mirror_set)
    only_in_mirror = list(mirror_set - true_set)
    for needs_add in only_in_true:
        action_list.append({
            'action': 'add',
            'address': needs_add
        })
    for needs_remove in only_in_mirror:
        action_list.append({
            'action': 'remove',
            'address': needs_remove
        })
    return action_list


def read_sanctioned_addresses(directory):
    """
    Read all sanctioned_addresses_*.txt files in the given directory
    and return a set of unique addresses.
    """
    unique_addresses = set()
    file_pattern = os.path.join(directory, 'sanctioned_addresses_*.txt')
    files = glob.glob(file_pattern)

    if not files:
        logger.warning(
            f"No sanctioned_addresses_*.txt files found in {directory}"
        )
        return unique_addresses

    logger.info(f"Found {len(files)} sanctioned address files")

    for file_path in files:
        try:
            with open(file_path) as f:
                addresses = [line.strip() for line in f if line.strip()]
                logger.info(f"Read {len(addresses)} addresses from {os.path.basename(file_path)}")
                unique_addresses.update(addresses)
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")

    logger.info(f"Total unique addresses: {len(unique_addresses)}")
    return unique_addresses


def get_s3_client(session):
    """Get thread-local S3 client"""
    if not hasattr(thread_local, 's3_client'):
        with boto3_client_lock:
            thread_local.s3_client = session.client('s3')
    return thread_local.s3_client


def create_s3_object(address, bucket, prefix, dry_run, s3_client):
    """Create a single empty S3 object for the given address."""
    object_key = f"{prefix}{encode(address)}"

    if dry_run:
        logger.info(f"DRY RUN: Would create S3 object s3://{bucket}/{object_key} ({address})")
        return True, None

    try:
        # Create an empty in-memory file-like object
        empty_file = BytesIO(b'')

        # Use upload_fileobj with default retry behavior
        s3_client.upload_fileobj(
            Fileobj=empty_file,
            Bucket=bucket,
            Key=object_key
        )
        return True, None
    except ClientError as e:
        return False, f"Error creating S3 object for {address}: {e}"


def delete_s3_object(address, bucket, prefix, dry_run, s3_client):
    """Delete an S3 object for the given address."""
    object_key = f"{prefix}{encode(address)}"
    if dry_run:
        logger.info(f"DRY RUN: Would delete S3 object s3://{bucket}/{object_key} ({address})")
        return True, None
    try:
        s3_client.delete_object(
            Bucket=bucket,
            Key=object_key
        )
        # Check if the object was actually deleted
        try:
            s3_client.head_object(Bucket=bucket, Key=object_key)
            return False, f"Failed to delete S3 object for {address}: Object still exists"
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                # 404. File is gone
                return True, None
            return False, f"Error verifying deletion for {address}: {e}"
    except ClientError as e:
        return False, f"Error deleting S3 object for {address}: {e}"


def process_action_chunk(action_chunk, bucket, prefix, dry_run, s3_client):
    """Process a chunk of actions."""
    results = {
        'created': 0,
        'removed': 0,
        'errors': 0
    }

    for action in action_chunk:
        created = False
        removed = False
        match action['action']:
            case 'add':
                created, error = create_s3_object(
                    action['address'],
                    bucket,
                    prefix,
                    dry_run,
                    s3_client
                )
            case 'remove':
                removed, error = delete_s3_object(
                    action['address'],
                    bucket,
                    prefix,
                    dry_run,
                    s3_client
                )
        if created:
            results['created'] += 1
        if removed:
            results['removed'] += 1
        else:
            results['errors'] += 1
            logger.error(error)

    return results


def reconcile_s3(
    actions,
    bucket,
    prefix,
    dry_run,
    s3_client,
    workers=NUM_WORKERS,
    chunk_size=CHUNK_SIZE
):
    """
    Reconcile the SDN and the S3 mirror so that they match by executing each
    action in the list.
    """
    action_list = list(actions)
    total_actions = len(action_list)

    logger.info(f"Starting to take {total_actions} actions on S3 objects using {workers} worker threads")

    # Create chunks of actions to process
    action_chunks = [action_list[i:i + chunk_size] for i in range(0, total_actions, chunk_size)]

    created_count = 0
    removed_count = 0
    error_count = 0

    # Use ThreadPoolExecutor to process chunks in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        # Submit all chunks to the executor
        future_to_chunk = {
            executor.submit(
                process_action_chunk, chunk, bucket, prefix, dry_run, s3_client
            ): i for i, chunk in enumerate(action_chunks)
        }

        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_chunk):
            chunk_index = future_to_chunk[future]
            try:
                results = future.result()
                created_count += results['created']
                removed_count += results['removed']
                error_count += results['errors']

                logger.info(
                    f"Completed chunk {chunk_index+1}/{len(action_chunks)}, "
                    f"total progress: {created_count + removed_count + error_count}/{total_actions} "
                    f"({(created_count + removed_count + error_count) / total_actions * 100:.1f}%)"
                )

            except Exception as e:
                logger.error(f"Exception processing chunk {chunk_index}: {e}")

    logger.info(f"Created {created_count} S3 objects")
    logger.info(f"Removed {removed_count} S3 objects")
    if error_count > 0:
        logger.warning(f"Failed to update {error_count} S3 objects")


def main():
    """
    Read the latest SND list, compare it to the addresses stored in S3, and
    reconcile the lists, using the SDN as the source of truth.
    """
    args = parse_arguments()

    session = boto3.Session()
    s3_client = get_s3_client(session)
    s3_resource = boto3.resource('s3')
    bucket = s3_resource.Bucket(args.bucket)

    # Read sanctioned addresses
    sdn_addresses = read_sanctioned_addresses(args.directory)
    s3_addresses = [obj.key for obj in bucket.objects.all()]

    if not sdn_addresses:
        logger.error("No addresses found in SDN list. Exiting.")
        return
    actions = generate_actions(sdn_addresses, s3_addresses)
    remove_count = sum(1 for a in actions if a['action'] == 'remove')
    total_count = len(s3_addresses)
    percent_removed = (remove_count / total_count) * 100
    if percent_removed > 15:
        if os.getenv('GITHUB_ACTOR') in ["mrose17", "Sneagan", "mschfh"]:
            logger.error(os.getenv('GITHUB_ACTOR'))
        logger.error("Too many addresses are set to be removed. Human review "
                     f'required.\nTotal addresses: {total_count}\nAddresses to'
                     f' remove: {remove_count}')
        raise Exception("Too many addresses are set to be removed. Human "
                        f'review required.\nTotal addresses: {total_count}\n'
                        f'Addresses to remove: {remove_count}')

    # Create S3 objects
    reconcile_s3(
        actions=actions,
        bucket=args.bucket,
        prefix=OBJECT_PREFIX,
        dry_run=args.dry_run,
        s3_client=s3_client,
        workers=NUM_WORKERS,
        chunk_size=CHUNK_SIZE
    )


if __name__ == "__main__":
    main()
