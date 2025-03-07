#!/usr/bin/env python3

import argparse
import concurrent.futures
import glob
import logging
import os
import threading
from io import BytesIO

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

# Constants
NUM_WORKERS = 10
CHUNK_SIZE = 100
OBJECT_PREFIX = ''

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Read sanctioned addresses from TXT files and create empty S3 objects.'
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
        help='S3 bucket name where objects will be created'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Perform a dry run without creating S3 objects'
    )
    return parser.parse_args()

def read_sanctioned_addresses(directory):
    """
    Read all sanctioned_addresses_*.txt files in the given directory
    and return a set of unique addresses.
    """
    unique_addresses = set()
    file_pattern = os.path.join(directory, 'sanctioned_addresses_*.txt')
    files = glob.glob(file_pattern)

    if not files:
        logger.warning(f"No sanctioned_addresses_*.txt files found in {directory}")
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
    """Get thread-local S3 client to ensure thread safety."""
    if not hasattr(thread_local, 's3_client'):
        thread_local.s3_client = session.client('s3')
    return thread_local.s3_client

def create_s3_object(address, bucket, prefix, dry_run, session):
    """Create a single empty S3 object for the given address."""
    object_key = f"{prefix}{address}"

    if dry_run:
        logger.debug(f"DRY RUN: Would create empty S3 object s3://{bucket}/{object_key}")
        return True, None

    try:
        # Get thread-local S3 client
        s3_client = get_s3_client(session)

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

def process_address_chunk(addresses_chunk, bucket, prefix, dry_run, session):
    """Process a chunk of addresses."""
    results = {
        'success': 0,
        'errors': 0
    }

    for address in addresses_chunk:
        success, error = create_s3_object(address, bucket, prefix, dry_run, session)
        if success:
            results['success'] += 1
        else:
            results['errors'] += 1
            logger.error(error)

    return results

def create_s3_objects(addresses, bucket, prefix, dry_run, session, workers=NUM_WORKERS, chunk_size=CHUNK_SIZE):
    """Create empty S3 objects for each address using thread pool."""
    addresses_list = list(addresses)
    total_addresses = len(addresses_list)

    logger.info(f"Starting to create {total_addresses} S3 objects using {workers} worker threads")

    # Create chunks of addresses to process
    address_chunks = [addresses_list[i:i + chunk_size] for i in range(0, total_addresses, chunk_size)]

    created_count = 0
    error_count = 0

    # Use ThreadPoolExecutor to process chunks in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        # Submit all chunks to the executor
        future_to_chunk = {
            executor.submit(
                process_address_chunk, chunk, bucket, prefix, dry_run, session
            ): i for i, chunk in enumerate(address_chunks)
        }

        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_chunk):
            chunk_index = future_to_chunk[future]
            try:
                results = future.result()
                created_count += results['success']
                error_count += results['errors']

                logger.info(f"Completed chunk {chunk_index+1}/{len(address_chunks)}, "
                           f"total progress: {created_count + error_count}/{total_addresses} "
                           f"({(created_count + error_count) / total_addresses * 100:.1f}%)")

            except Exception as e:
                logger.error(f"Exception processing chunk {chunk_index}: {e}")

    logger.info(f"Successfully created {created_count} S3 objects")
    if error_count > 0:
        logger.warning(f"Failed to create {error_count} S3 objects")

def main():
    args = parse_arguments()

    session = boto3.Session()

    # Read sanctioned addresses
    addresses = read_sanctioned_addresses(args.directory)

    if not addresses:
        logger.error("No addresses found. Exiting.")
        return

    # Create S3 objects
    create_s3_objects(
        addresses=addresses,
        bucket=args.bucket,
        prefix=OBJECT_PREFIX,
        dry_run=args.dry_run,
        session=session,
        workers=NUM_WORKERS,
        chunk_size=CHUNK_SIZE
    )

if __name__ == "__main__":
    main()
