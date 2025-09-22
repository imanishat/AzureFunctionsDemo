import azure.functions as func
import logging
import requests
from bs4 import BeautifulSoup
import os
import time
from urllib.parse import urljoin, urlparse
from collections import deque
import hashlib
from datetime import datetime
import json
from azure.storage.blob import BlobServiceClient
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

def get_secret_from_keyvault(secret_name: str) -> str:
    """Get secret from Azure Key Vault with fallback to environment variables"""
    try:
        # For Azure deployment, try Key Vault first
        if os.environ.get("WEBSITE_SITE_NAME"):  # Running in Azure
            vault_url = "https://kv-agenticai-demo.vault.azure.net/"
            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=vault_url, credential=credential)
            secret = client.get_secret(secret_name)
            return secret.value
        else:
            # For local development, use environment variables
            env_map = {
                "AzureStorageAccountName": "AZURE_STORAGE_ACCOUNT_NAME",
                "AzureStorageAccountKey": "AZURE_STORAGE_ACCOUNT_KEY", 
                "AzureStorageContainerName": "AZURE_STORAGE_CONTAINER_NAME",
                "TargetUrl": "TARGET_URL"
            }
            return os.environ.get(env_map.get(secret_name, secret_name))
    except Exception as e:
        logging.error(f"Error retrieving secret {secret_name}: {str(e)}")
        # Fallback to environment variable
        env_map = {
            "AzureStorageAccountName": "AZURE_STORAGE_ACCOUNT_NAME",
            "AzureStorageAccountKey": "AZURE_STORAGE_ACCOUNT_KEY", 
            "AzureStorageContainerName": "AZURE_STORAGE_CONTAINER_NAME",
            "TargetUrl": "TARGET_URL"
        }
        return os.environ.get(env_map.get(secret_name, secret_name))

@app.route(route="download_multiple_files")
def download_multiple_files(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Function triggered to crawl and upload all PDF and Word document files to Blob Storage.')

    try:
        # Get configuration from Key Vault
        target_url = get_secret_from_keyvault("TargetUrl") or 'https://rulebook.centralbank.ae/en'
        max_pages_to_crawl = 10  # Increased from 10 to crawl much more extensively
        max_depth = 2  # Increased from 2 to go much deeper

        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        })

        base_domain = urlparse(target_url).netloc
        urls_to_visit = deque([(target_url, 0)])
        visited_urls = set()
        all_document_links = []
        crawl_summary = []

        # Azure Blob Setup - Get credentials from Key Vault and use managed identity
        account_name = get_secret_from_keyvault("AzureStorageAccountName")
        container_name = get_secret_from_keyvault("AzureStorageContainerName")

        if not account_name or not container_name:
            raise ValueError("Missing required Azure Storage configuration")

        # Use different authentication based on environment
        if os.environ.get("WEBSITE_SITE_NAME"):  # Running in Azure
            logging.info("Running in Azure - using managed identity")
            # Use managed identity in Azure
            credential = DefaultAzureCredential()
        else:
            logging.info("Running locally - using Azure CLI credentials")
            # Use Azure CLI credentials for local development
            from azure.identity import AzureCliCredential
            credential = AzureCliCredential()
        
        blob_service_client = BlobServiceClient(
            account_url=f"https://{account_name}.blob.core.windows.net",
            credential=credential
        )
        blob_container_client = blob_service_client.get_container_client(container_name)

        # Function to create safe folder name from URL
        def create_safe_folder_name(url):
            """Create a safe folder name from webpage URL"""
            parsed_url = urlparse(url)
            # Use the path part of URL, or domain if no path
            path_part = parsed_url.path.strip('/') or parsed_url.netloc
            # Clean the path to create a safe folder name
            safe_name = ''.join(c for c in path_part if c.isalnum() or c in '.-_').strip()
            # Replace multiple special chars with single underscore
            import re
            safe_name = re.sub(r'[.-_]+', '_', safe_name)
            # Limit length and ensure it doesn't end with underscore
            safe_name = safe_name[:50].strip('_')
            return safe_name or 'unknown_page'

        # Function to load existing webpage metadata
        def load_existing_webpage_metadata():
            """Load existing webpage metadata from today's JSON files"""
            current_date = datetime.now()
            date_folder = current_date.strftime("%Y-%m-%d")
            existing_metadata = {}
            
            try:
                # List all JSON files in today's webpage folders
                blob_list = blob_container_client.list_blobs(name_starts_with=f"{date_folder}/")
                
                for blob in blob_list:
                    if blob.name.endswith('.json') and '/webpage_' in blob.name:
                        try:
                            # Download and parse the JSON file
                            blob_client = blob_container_client.get_blob_client(blob.name)
                            json_content = blob_client.download_blob().readall()
                            metadata = json.loads(json_content)
                            
                            # Store metadata indexed by webpage URL
                            webpage_url = metadata.get('webpage_url')
                            if webpage_url:
                                existing_metadata[webpage_url] = {
                                    'metadata': metadata,
                                    'blob_path': blob.name,
                                    'last_modified': blob.last_modified
                                }
                                
                        except Exception as e:
                            logging.error(f"Error loading metadata from {blob.name}: {str(e)}")
                            
                logging.info(f"Loaded metadata for {len(existing_metadata)} webpages from {date_folder}")
                return existing_metadata
                
            except Exception as e:
                logging.error(f"Error loading existing metadata: {str(e)}")
                return {}

        # Function to compare webpage content with existing metadata
        def has_webpage_changed(webpage_url, current_documents):
            """Compare current webpage documents with existing metadata to detect changes"""
            existing_metadata = load_existing_webpage_metadata()
            
            if webpage_url not in existing_metadata:
                logging.info(f"No existing metadata found for {webpage_url} - treating as new")
                return True
                
            existing_docs = existing_metadata[webpage_url]['metadata'].get('documents', [])
            
            # Create a set of document signatures for comparison
            def create_doc_signature(doc):
                return (
                    doc.get('download_url', ''),
                    doc.get('original_text', ''),
                    doc.get('type', ''),
                    doc.get('size', 0)
                )
            
            existing_signatures = {create_doc_signature(doc) for doc in existing_docs}
            current_signatures = {create_doc_signature(doc) for doc in current_documents}
            
            # Check if there are any differences
            has_changes = existing_signatures != current_signatures
            
            if has_changes:
                added = current_signatures - existing_signatures
                removed = existing_signatures - current_signatures
                logging.info(f"Changes detected for {webpage_url}: {len(added)} added, {len(removed)} removed")
            else:
                logging.info(f"No changes detected for {webpage_url}")
                
            return has_changes

        # Function to check if documents already exist for today
        def check_existing_documents_for_today():
            """Check if documents with today's date folder already exist in storage"""
            current_date = datetime.now()
            date_folder = current_date.strftime("%Y-%m-%d")
            existing_files = []
            
            try:
                # List all blobs in the date folder (all subfolders)
                blob_list = blob_container_client.list_blobs(name_starts_with=f"{date_folder}/")
                for blob in blob_list:
                    # Only include files in attachment subfolders
                    if '/attachment/' in blob.name:
                        existing_files.append({
                            'name': blob.name.split('/')[-1],  # Get filename from path
                            'path': blob.name,
                            'size': blob.size,
                            'last_modified': blob.last_modified
                        })
                        
                logging.info(f"Found {len(existing_files)} documents already uploaded today in {date_folder}/*/attachment/")
                return existing_files
                
            except Exception as e:
                logging.error(f"Error checking existing documents: {str(e)}")
                return []

        # Check for existing documents uploaded today
        existing_today_files = check_existing_documents_for_today()

        downloaded_files = []
        failed_downloads = []
        uploaded_hashes = set()
        skipped_files = []
        
        # Track document counts per webpage for sequential numbering
        webpage_document_counts = {}
        
        # Track webpage metadata for JSON creation
        webpage_metadata = {}
        
        # Get current date for folder structure
        current_date = datetime.now()
        date_folder = current_date.strftime("%Y-%m-%d")

        logging.info(f"Starting crawl at {target_url}")

        pages_crawled = 0
        while urls_to_visit and pages_crawled < max_pages_to_crawl:
            current_url, depth = urls_to_visit.popleft()
            if current_url in visited_urls or depth > max_depth:
                continue

            visited_urls.add(current_url)
            pages_crawled += 1

            try:
                response = session.get(current_url, timeout=30)
                if response.status_code != 200:
                    continue

                soup = BeautifulSoup(response.content, 'html.parser')
                page_document_links = []
                page_navigation_links = []

                for a in soup.find_all('a', href=True):
                    href = a['href']
                    text = a.text.strip()
                    full_url = urljoin(current_url, href) if not href.startswith('http') else href

                    is_document = False
                    doc_type = None

                    if (href.endswith('.pdf') or 'pdf' in href.lower() or 
                        'pdf' in text.lower()):
                        is_document = True
                        doc_type = 'PDF'
                    elif (href.endswith(('.doc', '.docx')) or 
                          'doc' in href.lower() or 
                          'word' in text.lower()):
                        is_document = True
                        doc_type = 'Word'

                    if is_document:
                        page_document_links.append({
                            'url': full_url,
                            'text': text,
                            'type': doc_type,
                            'source_page': current_url
                        })
                    elif (depth < max_depth and 
                          urlparse(full_url).netloc == base_domain and
                          full_url not in visited_urls and
                          not any(skip in full_url.lower() for skip in ['javascript:', 'mailto:', '#', '.jpg', '.png', '.css', '.js'])):
                        page_navigation_links.append(full_url)

                all_document_links.extend(page_document_links)
                for nav_url in page_navigation_links:
                    urls_to_visit.append((nav_url, depth + 1))

                crawl_summary.append({
                    'url': current_url,
                    'depth': depth,
                    'documents_found': len(page_document_links),
                    'navigation_links': len(page_navigation_links)
                })

                time.sleep(1)

            except Exception as e:
                logging.error(f"Error while crawling {current_url}: {e}")
                continue

        # Group documents by source webpage for change detection
        documents_by_webpage = {}
        for doc_info in all_document_links:
            source_page = doc_info['source_page']
            if source_page not in documents_by_webpage:
                documents_by_webpage[source_page] = []
            documents_by_webpage[source_page].append(doc_info)

        # Check for changes and process documents only if needed
        webpages_to_process = []
        unchanged_webpages = []
        
        for webpage_url, docs in documents_by_webpage.items():
            # Download documents to check their metadata
            temp_doc_metadata = []
            for doc_info in docs:
                try:
                    response = session.get(doc_info['url'], timeout=30)
                    if response.status_code == 200 and len(response.content) > 1000:
                        temp_doc_metadata.append({
                            'download_url': doc_info['url'],
                            'original_text': doc_info['text'],
                            'type': doc_info['type'],
                            'size': len(response.content)
                        })
                except Exception as e:
                    logging.error(f"Error checking document {doc_info['url']}: {str(e)}")
            
            # Check if this webpage has changes
            if has_webpage_changed(webpage_url, temp_doc_metadata):
                webpages_to_process.append(webpage_url)
                logging.info(f"Webpage has changes, will process: {webpage_url}")
            else:
                unchanged_webpages.append(webpage_url)
                logging.info(f"No changes detected, skipping: {webpage_url}")

        # Begin Uploads - only for webpages with changes
        for i, doc_info in enumerate(all_document_links):
            # Skip documents from unchanged webpages
            if doc_info['source_page'] not in webpages_to_process:
                skipped_files.append({
                    'filename': f"skipped_{doc_info['text'][:30]}",
                    'existing_file': 'unchanged_webpage',
                    'size': 0,
                    'url': doc_info['url'],
                    'text': doc_info['text'],
                    'type': doc_info['type'],
                    'source_page': doc_info['source_page'],
                    'reason': 'No changes detected in webpage content'
                })
                continue
            
            try:
                download_url = doc_info['url']
                response = session.get(download_url, timeout=30)

                if response.status_code != 200 or len(response.content) < 1000:
                    session.headers.update({'Referer': doc_info['source_page']})
                    response = session.get(download_url, timeout=30)

                if response.status_code == 200 and len(response.content) > 1000:
                    # De-duplication by hash
                    content_hash = hashlib.sha256(response.content).hexdigest()
                    if content_hash in uploaded_hashes:
                        continue
                    
                    ext = ".pdf" if doc_info['type'] == 'PDF' else (".docx" if 'docx' in download_url else ".doc")
                    
                    # Generate unique ID with current timestamp
                    unique_id = int(time.time() * 1000)  # Unique with milliseconds
                    
                    # Get the source page for grouping documents
                    source_page = doc_info['source_page']
                    
                    # Track document count for this webpage
                    if source_page not in webpage_document_counts:
                        webpage_document_counts[source_page] = 0
                    webpage_document_counts[source_page] += 1
                    document_sequence = webpage_document_counts[source_page]
                    
                    # Store webpage metadata for JSON creation
                    if source_page not in webpage_metadata:
                        webpage_metadata[source_page] = {
                            'url': source_page,
                            'unique_id': unique_id,
                            'crawl_date': current_date.isoformat(),
                            'documents': []
                        }
                    
                    safe_text = ''.join(c for c in doc_info['text'][:50] if c.isalnum() or c in ' -_').strip().replace(' ', '_')
                    
                    # New format: documentname_<uniqueid>_<sequence>.ext
                    if safe_text:
                        filename = f"{safe_text}_{unique_id}_{document_sequence}{ext}"
                        display_name = f"{safe_text}_{unique_id}_{document_sequence}{ext}"
                    else:
                        filename = f"document_{unique_id}_{document_sequence}{ext}"
                        display_name = f"document_{unique_id}_{document_sequence}{ext}"
                    
                    # Check if similar document already exists today (updated logic for new format)
                    document_exists = False
                    existing_doc_name = None
                    
                    for existing_file in existing_today_files:
                        # Check if document with similar name already exists today
                        existing_name = existing_file['name']
                        # Check if this is the same document by comparing the base name and unique ID
                        if safe_text and existing_name.startswith(f"{safe_text}_{unique_id}_"):
                            document_exists = True
                            existing_doc_name = existing_name
                            break
                        elif not safe_text and existing_name.startswith(f"document_{unique_id}_"):
                            document_exists = True
                            existing_doc_name = existing_name
                            break
                    
                    if document_exists:
                        # Document already exists today - skip upload
                        skipped_files.append({
                            'filename': display_name,
                            'existing_file': existing_doc_name,
                            'size': len(response.content),
                            'url': download_url,
                            'text': doc_info['text'],
                            'type': doc_info['type'],
                            'source_page': doc_info['source_page'],
                            'reason': f'Document already uploaded today as {existing_doc_name}'
                        })
                        logging.info(f"Skipping {display_name} - already exists as {existing_doc_name}")
                        continue
                    
                    uploaded_hashes.add(content_hash)
                    
                    # Create safe folder name for this webpage
                    webpage_folder_name = create_safe_folder_name(source_page)
                    
                    # Create the blob path with new folder structure: YYYY-MM-DD/webpage_name/attachment/
                    blob_path = f"{date_folder}/{webpage_folder_name}/attachment/{filename}"

                    blob_container_client.upload_blob(
                        name=blob_path,
                        data=response.content,
                        overwrite=False
                    )
                    
                    # Add document info to webpage metadata
                    webpage_metadata[source_page]['documents'].append({
                        'filename': filename,
                        'display_name': display_name,
                        'original_text': doc_info['text'],
                        'type': doc_info['type'],
                        'size': len(response.content),
                        'download_url': download_url,
                        'sequence': document_sequence,
                        'blob_path': blob_path
                    })

                    downloaded_files.append({
                        'filename': display_name,
                        'blob_filename': filename,
                        'size': len(response.content),
                        'url': download_url,
                        'text': doc_info['text'],
                        'type': doc_info['type'],
                        'source_page': doc_info['source_page'],
                        'blob_path': blob_path
                    })

                    time.sleep(1)
                else:
                    failed_downloads.append({
                        'url': download_url,
                        'text': doc_info['text'],
                        'type': doc_info['type'],
                        'source_page': doc_info['source_page'],
                        'status': response.status_code,
                        'size': len(response.content) if response.content else 0
                    })

            except Exception as e:
                failed_downloads.append({
                    'url': doc_info['url'],
                    'text': doc_info['text'],
                    'type': doc_info['type'],
                    'source_page': doc_info['source_page'],
                    'error': str(e)
                })

        # Create webpage JSON files for each source page
        webpage_json_files = []
        for source_page, metadata in webpage_metadata.items():
            if metadata['documents']:  # Only create JSON if there are documents
                # Generate unique ID for webpage
                webpage_unique_id = metadata['unique_id']
                webpage_folder_name = create_safe_folder_name(source_page)
                json_filename = f"webpage_{webpage_unique_id}.json"
                json_blob_path = f"{date_folder}/{webpage_folder_name}/webpage/{json_filename}"
                
                # Create JSON content
                json_content = {
                    'webpage_url': source_page,
                    'unique_id': webpage_unique_id,
                    'crawl_date': metadata['crawl_date'],
                    'total_documents': len(metadata['documents']),
                    'documents': metadata['documents']
                }
                
                try:
                    # Upload JSON file to blob storage
                    json_data = json.dumps(json_content, indent=2)
                    blob_container_client.upload_blob(
                        name=json_blob_path,
                        data=json_data,
                        overwrite=True
                    )
                    
                    webpage_json_files.append({
                        'filename': json_filename,
                        'blob_path': json_blob_path,
                        'source_page': source_page,
                        'webpage_folder': webpage_folder_name,
                        'document_count': len(metadata['documents'])
                    })
                    
                    logging.info(f"Created webpage JSON: {json_filename} for {source_page}")
                    
                except Exception as e:
                    logging.error(f"Error creating webpage JSON for {source_page}: {str(e)}")

        # 📋 Prepare Summary
        response_text = f"📘 Crawl Summary ({date_folder}):\n"
        response_text += f"📄 Pages crawled: {len(visited_urls)}\n"
        response_text += f"📋 Documents discovered: {len(all_document_links)}\n"
        response_text += f"🔄 Webpages with changes: {len(webpages_to_process)}\n"
        response_text += f"⚪ Webpages unchanged: {len(unchanged_webpages)}\n"
        response_text += f"✅ Successfully uploaded: {len(downloaded_files)} files\n"
        response_text += f"📄 Webpage JSON files created: {len(webpage_json_files)} files\n"
        response_text += f"⏭️ Skipped (no changes): {len([f for f in skipped_files if 'unchanged' in f.get('reason', '')])}\n"
        response_text += f"⏭️ Skipped (already exist): {len([f for f in skipped_files if 'unchanged' not in f.get('reason', '')])}\n"
        response_text += f"❌ Failed uploads: {len(failed_downloads)} files\n\n"
        
        if unchanged_webpages:
            response_text += f"⚪ Unchanged Webpages (skipped):\n"
            for webpage in unchanged_webpages:
                webpage_path = urlparse(webpage).path or urlparse(webpage).netloc
                response_text += f"  📄 {webpage_path}\n"
            response_text += "\n"
        
        if webpages_to_process:
            response_text += f"🔄 Processed Webpages (with changes):\n"
            for webpage in webpages_to_process:
                webpage_path = urlparse(webpage).path or urlparse(webpage).netloc
                response_text += f"  📄 {webpage_path}\n"
            response_text += "\n"
        
        response_text += f"📁 Folder Structure Created:\n"
        response_text += f"├── {date_folder}/\n"
        
        # Group files by webpage folder
        webpage_folders = {}
        for file_info in downloaded_files:
            webpage_folder = create_safe_folder_name(file_info['source_page'])
            if webpage_folder not in webpage_folders:
                webpage_folders[webpage_folder] = {'attachments': [], 'json_files': []}
            webpage_folders[webpage_folder]['attachments'].append(file_info)
        
        for json_file in webpage_json_files:
            webpage_folder = json_file['webpage_folder']
            if webpage_folder not in webpage_folders:
                webpage_folders[webpage_folder] = {'attachments': [], 'json_files': []}
            webpage_folders[webpage_folder]['json_files'].append(json_file)
        
        for webpage_folder, files in webpage_folders.items():
            response_text += f"│   ├── {webpage_folder}/\n"
            if files['json_files']:
                response_text += f"│   │   ├── webpage/\n"
                for json_file in files['json_files']:
                    response_text += f"│   │   │   └── {json_file['filename']}\n"
            if files['attachments']:
                response_text += f"│   │   └── attachment/\n"
                for file_info in files['attachments']:
                    response_text += f"│   │       └── {file_info['blob_filename']}\n"
        response_text += "\n"

        # Show existing files information
        if existing_today_files:
            response_text += f"📅 Files already uploaded today ({date_folder}):\n"
            for existing_file in existing_today_files:
                response_text += f"  📄 {existing_file['name']} ({existing_file['size']:,} bytes)\n"
            response_text += "\n"

        if downloaded_files:
            response_text += "📁 Newly Uploaded Files:\n"
            total_size = 0
            pdf_count = sum(1 for f in downloaded_files if f['type'] == 'PDF')
            word_count = sum(1 for f in downloaded_files if f['type'] == 'Word')
            response_text += f"   📊 {pdf_count} PDF files, {word_count} Word files\n\n"

            for file_info in downloaded_files:
                type_icon = "📄" if file_info['type'] == 'PDF' else "📝"
                response_text += f"  {type_icon} {file_info['filename']}\n"
                response_text += f"    📁 Storage: {file_info['blob_path']}\n"
                response_text += f"    📏 Size: {file_info['size']:,} bytes\n"
                response_text += f"    📝 {file_info['text'][:50]}{'...' if len(file_info['text']) > 50 else ''}\n"
                response_text += f"    🔗 Source: {urlparse(file_info['source_page']).path}\n"
                total_size += file_info['size']
            response_text += f"\n📦 Total uploaded: {total_size:,} bytes (~{total_size/1024/1024:.2f} MB)\n"
        
        if webpage_json_files:
            response_text += "\n📄 Webpage JSON Files Created:\n"
            for json_info in webpage_json_files:
                response_text += f"  📄 {json_info['filename']} ({json_info['document_count']} documents)\n"
                response_text += f"    📁 Storage: {json_info['blob_path']}\n"
                response_text += f"    🔗 Source: {urlparse(json_info['source_page']).path}\n"

        if skipped_files:
            response_text += "\n⏭️ Skipped Files (Already Exist Today):\n"
            for file_info in skipped_files:
                type_icon = "📄" if file_info['type'] == 'PDF' else "📝"
                response_text += f"  {type_icon} {file_info['filename']} → {file_info['existing_file']}\n"
                response_text += f"    📝 {file_info['text'][:50]}{'...' if len(file_info['text']) > 50 else ''}\n"

        if failed_downloads:
            response_text += "\n❌ Failed Uploads:\n"
            for fail_info in failed_downloads:
                type_icon = "📄" if fail_info['type'] == 'PDF' else "📝"
                response_text += f"  {type_icon} {fail_info['text'][:50]}{'...' if len(fail_info['text']) > 50 else ''}\n"
                if 'error' in fail_info:
                    response_text += f"    ❗ Error: {fail_info['error']}\n"
                else:
                    response_text += f"    ❗ Status: {fail_info['status']}, Size: {fail_info['size']} bytes\n"

        response_text += f"\n🔍 Crawl Details:\n"
        for summary in crawl_summary:
            response_text += f"  • {urlparse(summary['url']).path} (depth {summary['depth']}): {summary['documents_found']} docs\n"

        if downloaded_files:
            return func.HttpResponse(response_text, status_code=200)
        else:
            return func.HttpResponse(f"No files could be uploaded.\n{response_text}", status_code=202)

    except Exception as e:
        logging.error(f"Unhandled error: {str(e)}")
        return func.HttpResponse(f"Internal server error: {str(e)}", status_code=500)
