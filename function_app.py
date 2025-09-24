import azure.functions as func
import azure.durable_functions as df
import logging
import requests
from bs4 import BeautifulSoup
import os
import time
from urllib.parse import urljoin, urlparse
from collections import deque
import hashlib
from datetime import datetime, timedelta
import json
from azure.storage.blob import BlobServiceClient
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from typing import List, Dict, Any

app = df.DFApp(http_auth_level=func.AuthLevel.ANONYMOUS)

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

# HTTP Starter Function - Triggers the durable orchestration
@app.route(route="crawl_website", methods=["GET", "POST"])
@app.durable_client_input(client_name="client")
async def crawl_website_starter(req: func.HttpRequest, client) -> func.HttpResponse:
    """HTTP starter function that begins the durable orchestration for web crawling."""
    logging.info('Durable Functions web crawler started.')
    
    try:
        # Get target URL from request or use default
        target_url = req.params.get('url')
        if not target_url:
            req_body = req.get_json()
            if req_body:
                target_url = req_body.get('url')
        
        if not target_url:
            target_url = get_secret_from_keyvault("TargetUrl") or 'https://rulebook.centralbank.ae/en'
        
        # Start the orchestration
        instance_id = await client.start_new("website_crawler_orchestrator", None, {
            "target_url": target_url,
            "max_depth": 5,  # Removed page limit, increased depth
            "start_time": datetime.now().isoformat()
        })
        
        logging.info(f"Started orchestration with ID = '{instance_id}'")
        
        # Return the management URLs for monitoring
        return client.create_check_status_response(req, instance_id)
        
    except Exception as e:
        logging.error(f"Error starting orchestration: {str(e)}")
        return func.HttpResponse(f"Error starting crawl: {str(e)}", status_code=500)

# Orchestrator Function - Coordinates the entire crawling workflow
@app.orchestration_trigger(context_name="context")
def website_crawler_orchestrator(context: df.DurableOrchestrationContext):
    """Main orchestrator that manages the web crawling workflow."""
    
    # Get input parameters
    input_data = context.get_input()
    target_url = input_data.get("target_url")
    max_depth = input_data.get("max_depth", 5)
    start_time = input_data.get("start_time")
    
    logging.info(f"Orchestrator started for URL: {target_url}")
    
    try:
        # Initialize crawling state
        crawl_state = {
            "target_url": target_url,
            "max_depth": max_depth,
            "visited_urls": [],
            "pending_urls": [{"url": target_url, "depth": 0}],
            "all_documents": [],
            "processed_count": 0,
            "start_time": start_time
        }
        
        # Phase 1: Discover all URLs and documents in the website
        crawl_result = yield context.call_activity("discover_website_structure", crawl_state)
        
        # Phase 2: Check for changes using metadata comparison
        change_detection_result = yield context.call_activity("detect_content_changes", {
            "documents_by_webpage": crawl_result["documents_by_webpage"],
            "crawl_info": crawl_result["crawl_info"]
        })
        
        # Phase 3: Process documents that have changes (Fan-out pattern)
        if change_detection_result["webpages_to_process"]:
            # Process documents in parallel batches to avoid overwhelming the system
            document_tasks = []
            batch_size = 5  # Process 5 webpages in parallel
            
            webpages_to_process = change_detection_result["webpages_to_process"]
            
            for i in range(0, len(webpages_to_process), batch_size):
                batch = webpages_to_process[i:i + batch_size]
                
                # Create parallel tasks for this batch
                batch_tasks = []
                for webpage_data in batch:
                    task = context.call_activity("process_webpage_documents", webpage_data)
                    batch_tasks.append(task)
                
                # Wait for this batch to complete before starting the next
                batch_results = yield context.task_all(batch_tasks)
                document_tasks.extend(batch_results)
                
                # Add a small delay between batches
                delay_until = context.current_utc_datetime + timedelta(seconds=2)
                yield context.create_timer(delay_until)
        
        else:
            document_tasks = []
        
        # Phase 4: Generate final summary
        summary_data = {
            "crawl_info": crawl_result["crawl_info"],
            "change_detection": change_detection_result,
            "processed_documents": document_tasks,
            "start_time": start_time,
            "end_time": datetime.now().isoformat()
        }
        
        final_summary = yield context.call_activity("generate_crawl_summary", summary_data)
        
        logging.info(f"Orchestration completed successfully for {target_url}")
        return final_summary
        
    except Exception as e:
        logging.error(f"Orchestrator error: {str(e)}")
        return f"Orchestration failed: {str(e)}"

# Activity Function 1: Discover website structure
@app.activity_trigger(input_name="crawl_state")
def discover_website_structure(crawl_state: dict) -> dict:
    """Activity function to discover all URLs and documents in the website."""
    logging.info("Starting website structure discovery")
    
    target_url = crawl_state["target_url"]
    max_depth = crawl_state["max_depth"]
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    })

    base_domain = urlparse(target_url).netloc
    urls_to_visit = deque([(target_url, 0)])
    visited_urls = set()
    all_document_links = []
    crawl_summary = []
    documents_by_webpage = {}

    logging.info(f"Starting comprehensive crawl at {target_url}")
    
    # Crawl without page limits - let it discover the entire site structure
    while urls_to_visit:
        current_url, depth = urls_to_visit.popleft()
        if current_url in visited_urls or depth > max_depth:
            continue

        visited_urls.add(current_url)

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
            
            # Group documents by source webpage
            if page_document_links:
                if current_url not in documents_by_webpage:
                    documents_by_webpage[current_url] = []
                documents_by_webpage[current_url].extend(page_document_links)

            time.sleep(0.5)  # Reduced delay for faster crawling

        except Exception as e:
            logging.error(f"Error while crawling {current_url}: {e}")
            continue

    logging.info(f"Discovery completed: {len(visited_urls)} pages, {len(all_document_links)} documents")
    
    return {
        "crawl_info": {
            "pages_crawled": len(visited_urls),
            "documents_discovered": len(all_document_links),
            "crawl_summary": crawl_summary
        },
        "documents_by_webpage": documents_by_webpage,
        "all_document_links": all_document_links
    }

# Activity Function 2: Detect content changes
@app.activity_trigger(input_name="detection_data")
def detect_content_changes(detection_data: dict) -> dict:
    """Activity function to detect changes in webpage content."""
    logging.info("Starting content change detection")
    
    documents_by_webpage = detection_data["documents_by_webpage"]
    crawl_info = detection_data["crawl_info"]
    
    # Azure Blob Setup for metadata checking
    account_name = get_secret_from_keyvault("AzureStorageAccountName")
    container_name = get_secret_from_keyvault("AzureStorageContainerName")
    
    if not account_name or not container_name:
        raise ValueError("Missing required Azure Storage configuration")

    # Use different authentication based on environment
    if os.environ.get("WEBSITE_SITE_NAME"):  # Running in Azure
        credential = DefaultAzureCredential()
    else:
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

    # Check for changes and prepare webpages to process
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    })
    
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
        existing_metadata = load_existing_webpage_metadata()
        
        if webpage_url not in existing_metadata:
            has_changes = True
            logging.info(f"No existing metadata found for {webpage_url} - treating as new")
        else:
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
            current_signatures = {create_doc_signature(doc) for doc in temp_doc_metadata}
            
            has_changes = existing_signatures != current_signatures
            
            if has_changes:
                added = current_signatures - existing_signatures
                removed = existing_signatures - current_signatures
                logging.info(f"Changes detected for {webpage_url}: {len(added)} added, {len(removed)} removed")
            else:
                logging.info(f"No changes detected for {webpage_url}")
        
        if has_changes:
            webpages_to_process.append({
                "webpage_url": webpage_url,
                "documents": docs,
                "webpage_folder": create_safe_folder_name(webpage_url)
            })
            logging.info(f"Webpage has changes, will process: {webpage_url}")
        else:
            unchanged_webpages.append(webpage_url)
            logging.info(f"No changes detected, skipping: {webpage_url}")
    
    return {
        "webpages_to_process": webpages_to_process,
        "unchanged_webpages": unchanged_webpages,
        "total_webpages": len(documents_by_webpage)
    }

# Activity Function 3: Process webpage documents
@app.activity_trigger(input_name="webpage_data")
def process_webpage_documents(webpage_data: dict) -> dict:
    """Activity function to process and upload documents from a specific webpage."""
    webpage_url = webpage_data["webpage_url"]
    documents = webpage_data["documents"]
    webpage_folder = webpage_data["webpage_folder"]
    
    logging.info(f"Processing documents for webpage: {webpage_url}")
    
    # Azure Blob Setup
    account_name = get_secret_from_keyvault("AzureStorageAccountName")
    container_name = get_secret_from_keyvault("AzureStorageContainerName")
    
    if not account_name or not container_name:
        raise ValueError("Missing required Azure Storage configuration")

    if os.environ.get("WEBSITE_SITE_NAME"):  # Running in Azure
        credential = DefaultAzureCredential()
    else:
        from azure.identity import AzureCliCredential
        credential = AzureCliCredential()
    
    blob_service_client = BlobServiceClient(
        account_url=f"https://{account_name}.blob.core.windows.net",
        credential=credential
    )
    blob_container_client = blob_service_client.get_container_client(container_name)
    
    # Session for downloading documents
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    })
    
    # Get current date for folder structure
    current_date = datetime.now()
    date_folder = current_date.strftime("%Y-%m-%d")
    
    # Track results
    downloaded_files = []
    failed_downloads = []
    uploaded_hashes = set()
    
    # Process each document
    for i, doc_info in enumerate(documents):
        try:
            download_url = doc_info['url']
            response = session.get(download_url, timeout=30)

            if response.status_code != 200 or len(response.content) < 1000:
                session.headers.update({'Referer': webpage_url})
                response = session.get(download_url, timeout=30)

            if response.status_code == 200 and len(response.content) > 1000:
                # De-duplication by hash
                content_hash = hashlib.sha256(response.content).hexdigest()
                if content_hash in uploaded_hashes:
                    continue
                
                ext = ".pdf" if doc_info['type'] == 'PDF' else (".docx" if 'docx' in download_url else ".doc")
                
                # Generate unique ID with current timestamp
                unique_id = int(time.time() * 1000)  # Unique with milliseconds
                document_sequence = i + 1  # Sequential numbering for this webpage
                
                safe_text = ''.join(c for c in doc_info['text'][:50] if c.isalnum() or c in ' -_').strip().replace(' ', '_')
                
                # New format: documentname_<uniqueid>_<sequence>.ext
                if safe_text:
                    filename = f"{safe_text}_{unique_id}_{document_sequence}{ext}"
                    display_name = f"{safe_text}_{unique_id}_{document_sequence}{ext}"
                else:
                    filename = f"document_{unique_id}_{document_sequence}{ext}"
                    display_name = f"document_{unique_id}_{document_sequence}{ext}"
                
                uploaded_hashes.add(content_hash)
                
                # Create the blob path with new folder structure: YYYY-MM-DD/webpage_name/attachment/
                blob_path = f"{date_folder}/{webpage_folder}/attachment/{filename}"

                blob_container_client.upload_blob(
                    name=blob_path,
                    data=response.content,
                    overwrite=False
                )

                downloaded_files.append({
                    'filename': display_name,
                    'blob_filename': filename,
                    'size': len(response.content),
                    'url': download_url,
                    'text': doc_info['text'],
                    'type': doc_info['type'],
                    'source_page': webpage_url,
                    'blob_path': blob_path
                })

                time.sleep(0.5)  # Small delay between uploads
            else:
                failed_downloads.append({
                    'url': download_url,
                    'text': doc_info['text'],
                    'type': doc_info['type'],
                    'source_page': webpage_url,
                    'status': response.status_code,
                    'size': len(response.content) if response.content else 0
                })

        except Exception as e:
            failed_downloads.append({
                'url': doc_info['url'],
                'text': doc_info['text'],
                'type': doc_info['type'],
                'source_page': webpage_url,
                'error': str(e)
            })
    
    # Create webpage JSON file if documents were processed
    webpage_json_result = None
    if downloaded_files:
        try:
            unique_id = int(time.time() * 1000)
            json_filename = f"webpage_{unique_id}.json"
            json_blob_path = f"{date_folder}/{webpage_folder}/webpage/{json_filename}"
            
            # Create JSON content
            json_content = {
                'webpage_url': webpage_url,
                'unique_id': unique_id,
                'crawl_date': current_date.isoformat(),
                'total_documents': len(downloaded_files),
                'documents': [
                    {
                        'filename': file_info['blob_filename'],
                        'display_name': file_info['filename'],
                        'original_text': file_info['text'],
                        'type': file_info['type'],
                        'size': file_info['size'],
                        'download_url': file_info['url'],
                        'blob_path': file_info['blob_path']
                    }
                    for file_info in downloaded_files
                ]
            }
            
            # Upload JSON file to blob storage
            json_data = json.dumps(json_content, indent=2)
            blob_container_client.upload_blob(
                name=json_blob_path,
                data=json_data,
                overwrite=True
            )
            
            webpage_json_result = {
                'filename': json_filename,
                'blob_path': json_blob_path,
                'document_count': len(downloaded_files)
            }
            
            logging.info(f"Created webpage JSON: {json_filename} for {webpage_url}")
            
        except Exception as e:
            logging.error(f"Error creating webpage JSON for {webpage_url}: {str(e)}")
    
    logging.info(f"Processed webpage {webpage_url}: {len(downloaded_files)} uploaded, {len(failed_downloads)} failed")
    
    return {
        "webpage_url": webpage_url,
        "webpage_folder": webpage_folder,
        "downloaded_files": downloaded_files,
        "failed_downloads": failed_downloads,
        "webpage_json": webpage_json_result
    }

# Activity Function 4: Generate final summary
@app.activity_trigger(input_name="summary_data")
def generate_crawl_summary(summary_data: dict) -> str:
    """Generate the final crawl summary."""
    crawl_info = summary_data["crawl_info"]
    change_detection = summary_data["change_detection"]
    processed_documents = summary_data["processed_documents"]
    start_time = summary_data["start_time"]
    end_time = summary_data["end_time"]
    
    current_date = datetime.now()
    date_folder = current_date.strftime("%Y-%m-%d")
    
    # Aggregate results from all processed webpages
    total_downloaded = 0
    total_failed = 0
    all_downloaded_files = []
    all_failed_downloads = []
    webpage_json_files = []
    
    for result in processed_documents:
        if result:
            total_downloaded += len(result.get("downloaded_files", []))
            total_failed += len(result.get("failed_downloads", []))
            all_downloaded_files.extend(result.get("downloaded_files", []))
            all_failed_downloads.extend(result.get("failed_downloads", []))
            if result.get("webpage_json"):
                webpage_json_files.append(result["webpage_json"])
    
    # 📋 Prepare Summary
    response_text = f"📘 Durable Functions Crawl Summary ({date_folder}):\n"
    response_text += f"⏱️ Duration: {start_time} to {end_time}\n"
    response_text += f"📄 Pages crawled: {crawl_info['pages_crawled']}\n"
    response_text += f"📋 Documents discovered: {crawl_info['documents_discovered']}\n"
    response_text += f"🔄 Webpages with changes: {len(change_detection['webpages_to_process'])}\n"
    response_text += f"⚪ Webpages unchanged: {len(change_detection['unchanged_webpages'])}\n"
    response_text += f"✅ Successfully uploaded: {total_downloaded} files\n"
    response_text += f"📄 Webpage JSON files created: {len(webpage_json_files)} files\n"
    response_text += f"❌ Failed uploads: {total_failed} files\n\n"
    
    if change_detection['unchanged_webpages']:
        response_text += f"⚪ Unchanged Webpages (skipped):\n"
        for webpage in change_detection['unchanged_webpages']:
            webpage_path = urlparse(webpage).path or urlparse(webpage).netloc
            response_text += f"  📄 {webpage_path}\n"
        response_text += "\n"
    
    if all_downloaded_files:
        response_text += "📁 Newly Uploaded Files:\n"
        total_size = 0
        pdf_count = sum(1 for f in all_downloaded_files if f['type'] == 'PDF')
        word_count = sum(1 for f in all_downloaded_files if f['type'] == 'Word')
        response_text += f"   📊 {pdf_count} PDF files, {word_count} Word files\n\n"

        for file_info in all_downloaded_files:
            type_icon = "📄" if file_info['type'] == 'PDF' else "📝"
            response_text += f"  {type_icon} {file_info['filename']}\n"
            response_text += f"    📁 Storage: {file_info['blob_path']}\n"
            response_text += f"    📏 Size: {file_info['size']:,} bytes\n"
            response_text += f"    📝 {file_info['text'][:50]}{'...' if len(file_info['text']) > 50 else ''}\n"
            total_size += file_info['size']
        response_text += f"\n📦 Total uploaded: {total_size:,} bytes (~{total_size/1024/1024:.2f} MB)\n"
    
    if webpage_json_files:
        response_text += "\n📄 Webpage JSON Files Created:\n"
        for json_info in webpage_json_files:
            response_text += f"  📄 {json_info['filename']} ({json_info['document_count']} documents)\n"
            response_text += f"    📁 Storage: {json_info['blob_path']}\n"

    if all_failed_downloads:
        response_text += "\n❌ Failed Uploads:\n"
        for fail_info in all_failed_downloads:
            type_icon = "📄" if fail_info['type'] == 'PDF' else "📝"
            response_text += f"  {type_icon} {fail_info['text'][:50]}{'...' if len(fail_info['text']) > 50 else ''}\n"
            if 'error' in fail_info:
                response_text += f"    ❗ Error: {fail_info['error']}\n"
            else:
                response_text += f"    ❗ Status: {fail_info['status']}, Size: {fail_info['size']} bytes\n"

    response_text += f"\n🔍 Crawl Details:\n"
    for summary in crawl_info['crawl_summary']:
        response_text += f"  • {urlparse(summary['url']).path} (depth {summary['depth']}): {summary['documents_found']} docs\n"
    
    response_text += f"\n🎉 Durable Functions crawl completed successfully!\n"
    response_text += f"📊 Total processing time: {start_time} to {end_time}\n"
    
    return response_text
