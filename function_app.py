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
from azure.storage.blob import BlobServiceClient, ContentSettings
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

# Simple test endpoint to see if function is working
@app.route(route="test", methods=["GET"])
def test_function(req: func.HttpRequest) -> func.HttpResponse:
    """Simple test endpoint to verify the function is working."""
    return func.HttpResponse("🎉 Durable Functions are working! The crawler is running in the background.", status_code=200)

# Quick test crawl endpoint for smaller websites
@app.route(route="test_crawl", methods=["GET", "POST"])
@app.durable_client_input(client_name="client")
async def test_crawl_starter(req: func.HttpRequest, client) -> func.HttpResponse:
    """Test crawler with a smaller, simpler website."""
    logging.info('Test crawler started.')
    
    try:
        # Use a simple website for testing
        target_url = req.params.get('url', 'https://example.com')
        
        # Start the orchestration with limited scope
        instance_id = await client.start_new("website_crawler_orchestrator", None, {
            "target_url": target_url,
            "max_depth": 2,  # Limited depth for testing
            "start_time": datetime.now().isoformat()
        })
        
        logging.info(f"Started test orchestration with ID = '{instance_id}'")
        
        # Return the management URLs for monitoring
        return client.create_check_status_response(req, instance_id)
        
    except Exception as e:
        logging.error(f"Error starting test orchestration: {str(e)}")
        return func.HttpResponse(f"Error starting test crawl: {str(e)}", status_code=500)

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
            try:
                req_body = req.get_json()
                if req_body:
                    target_url = req_body.get('url')
            except ValueError:
                # No JSON body or invalid JSON - this is fine for GET requests
                pass
        
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
    
    # Add time limit to prevent infinite crawling, but no page limit for unlimited crawling
    MAX_TIME_MINUTES = 30  # Increased time limit to 30 minutes for comprehensive crawling
    start_time = time.time()

    logging.info(f"Starting unlimited crawl at {target_url} (max time: {MAX_TIME_MINUTES} min, no page limit)")
    
    page_count = 0
    while urls_to_visit:  # Removed page count limit for unlimited crawling
        # Check time limit
        elapsed_minutes = (time.time() - start_time) / 60
        if elapsed_minutes > MAX_TIME_MINUTES:
            logging.warning(f"Crawl time limit reached ({MAX_TIME_MINUTES} minutes). Stopping crawl.")
            break
            
        current_url, depth = urls_to_visit.popleft()
        if current_url in visited_urls or depth > max_depth:
            continue

        visited_urls.add(current_url)
        page_count += 1

        # Log progress every 10 pages
        if page_count % 10 == 0:
            logging.info(f"Progress: Crawled {page_count} pages, found {len(all_document_links)} documents, {len(urls_to_visit)} pending URLs")

        try:
            logging.info(f"Crawling page {page_count}: {current_url} (depth: {depth})")
            response = session.get(current_url, timeout=15)  # Reduced timeout
            if response.status_code != 200:
                logging.warning(f"Page returned status {response.status_code}: {current_url}")
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
            
            # Group documents by source webpage AND upload them immediately
            if page_document_links:
                if current_url not in documents_by_webpage:
                    documents_by_webpage[current_url] = []
                documents_by_webpage[current_url].extend(page_document_links)
                logging.info(f"Found {len(page_document_links)} documents on {current_url}")
                
                # IMMEDIATE UPLOAD: Process and upload documents as soon as they're found
                try:
                    webpage_data = {
                        "webpage_url": current_url,
                        "documents": page_document_links,
                        "metadata": {
                            "crawl_timestamp": datetime.now().isoformat(),
                            "page_depth": depth,
                            "page_count": page_count
                        }
                    }
                    upload_result = process_webpage_documents_immediate(webpage_data)
                    logging.info(f"✅ Immediately uploaded {len(page_document_links)} documents from {current_url}")
                except Exception as upload_error:
                    logging.error(f"❌ Failed to upload documents from {current_url}: {upload_error}")

            time.sleep(0.2)  # Shorter delay for faster crawling

        except requests.exceptions.Timeout:
            logging.warning(f"Timeout while crawling {current_url}")
            continue
        except requests.exceptions.RequestException as e:
            logging.error(f"Network error while crawling {current_url}: {e}")
            continue
        except Exception as e:
            logging.error(f"Unexpected error while crawling {current_url}: {e}")
            continue

    elapsed_time = (time.time() - start_time) / 60
    logging.info(f"Discovery completed: {len(visited_urls)} pages crawled, {len(all_document_links)} documents found in {elapsed_time:.1f} minutes")
    
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
    
    # Skip Azure Blob setup for local testing - treat all webpages as new
    logging.info("Local testing mode - skipping Azure Blob metadata checking")
    
    # For local testing, we'll skip the storage authentication
    blob_container_client = None

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

    # Function to load existing webpage metadata (simplified for local testing)
    def load_existing_webpage_metadata():
        """Load existing webpage metadata - simplified for local testing"""
        logging.info("Local testing mode - treating all webpages as new")
        return {}  # Return empty dict so all webpages are treated as new

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
        
        # For local testing, always treat webpages as having changes (new)
        has_changes = True
        logging.info(f"Local testing mode: treating {webpage_url} as new webpage with changes")
        
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

# Immediate upload function (called directly, not as activity trigger)
def process_webpage_documents_immediate(webpage_data: dict) -> dict:
    """Immediately process and upload documents from a webpage (called inline during crawling)."""
    webpage_url = webpage_data["webpage_url"]
    documents = webpage_data["documents"]
    metadata = webpage_data.get("metadata", {})
    
    # Create safe folder name from URL
    def create_safe_folder_name(url):
        parsed_url = urlparse(url)
        path_parts = [part for part in parsed_url.path.strip('/').split('/') if part]
        if path_parts:
            folder_name = path_parts[-1][:30]  # Last part of path, limited to 30 chars
        else:
            folder_name = parsed_url.netloc.replace('.', '_').replace('-', '_')[:30]
        
        safe_folder = ''.join(c for c in folder_name if c.isalnum() or c == '_')
        return safe_folder or "webpage"
    
    webpage_folder = create_safe_folder_name(webpage_url)
    
    logging.info(f"🚀 IMMEDIATE PROCESSING: {len(documents)} documents from {webpage_url}")
    
    # Initialize Azure Blob Storage client
    blob_container_client = None
    try:
        account_name = get_secret_from_keyvault("AzureStorageAccountName")
        container_name = get_secret_from_keyvault("AzureStorageContainerName")
        
        if account_name and container_name:
            try:
                credential = DefaultAzureCredential()
                blob_service_client = BlobServiceClient(
                    account_url=f"https://{account_name}.blob.core.windows.net",
                    credential=credential
                )
                blob_container_client = blob_service_client.get_container_client(container_name)
                logging.info(f"Azure Storage ready for immediate upload")
            except Exception as auth_error:
                logging.error(f"Azure AD auth failed for immediate upload: {str(auth_error)}")
                blob_container_client = None
        else:
            logging.warning("No Azure Storage config - using local storage for immediate upload")
                
    except Exception as e:
        logging.error(f"Storage init failed for immediate upload: {str(e)}")
    
    # Session for downloading documents
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
    
    # Get current date for folder structure
    current_date = datetime.now()
    date_folder = current_date.strftime("%Y-%m-%d")
    
    downloaded_files = []
    failed_downloads = []
    uploaded_hashes = set()
    
    # Process each document immediately
    for i, doc_info in enumerate(documents):
        try:
            download_url = doc_info['url']
            response = session.get(download_url, timeout=15)  # Shorter timeout for immediate processing

            if response.status_code != 200 or len(response.content) < 1000:
                session.headers.update({'Referer': webpage_url})
                response = session.get(download_url, timeout=15)

            if response.status_code == 200 and len(response.content) > 1000:
                # De-duplication by hash
                content_hash = hashlib.sha256(response.content).hexdigest()
                if content_hash in uploaded_hashes:
                    continue
                
                ext = ".pdf" if doc_info['type'] == 'PDF' else (".docx" if 'docx' in download_url else ".doc")
                unique_id = int(time.time() * 1000)
                document_sequence = i + 1
                
                safe_text = ''.join(c for c in doc_info['text'][:50] if c.isalnum() or c in ' -_').strip().replace(' ', '_')
                filename = f"{safe_text}_{unique_id}_{document_sequence}{ext}" if safe_text else f"document_{unique_id}_{document_sequence}{ext}"
                
                uploaded_hashes.add(content_hash)
                blob_path = f"{date_folder}/{webpage_folder}/attachment/{filename}"

                # Upload immediately
                if blob_container_client:
                    try:
                        blob_client = blob_container_client.get_blob_client(blob_path)
                        blob_client.upload_blob(
                            response.content, 
                            overwrite=True,
                            content_settings=ContentSettings(content_type='application/pdf' if ext == '.pdf' else 'application/octet-stream')
                        )
                        logging.info(f"⚡ IMMEDIATE UPLOAD: {filename} ({len(response.content)} bytes)")
                    except Exception as upload_error:
                        logging.error(f"❌ Immediate upload failed for {filename}: {str(upload_error)}")
                else:
                    # Local save
                    try:
                        local_path = os.path.join("downloads", blob_path)
                        os.makedirs(os.path.dirname(local_path), exist_ok=True)
                        with open(local_path, 'wb') as f:
                            f.write(response.content)
                        logging.info(f"⚡ IMMEDIATE SAVE: {filename} to local storage")
                    except Exception as local_error:
                        logging.error(f"❌ Immediate local save failed: {str(local_error)}")

                downloaded_files.append({
                    'filename': filename,
                    'size': len(response.content),
                    'url': download_url,
                    'type': doc_info['type'],
                    'blob_path': blob_path
                })

            else:
                failed_downloads.append({
                    'url': download_url,
                    'status': response.status_code,
                    'size': len(response.content) if response.content else 0
                })

        except Exception as e:
            failed_downloads.append({
                'url': doc_info['url'],
                'error': str(e)
            })
    
    # Create webpage JSON metadata file if documents were processed
    webpage_json_result = None
    if downloaded_files:
        try:
            unique_id = int(time.time() * 1000)
            json_filename = f"webpage_{unique_id}.json"
            json_blob_path = f"{date_folder}/{webpage_folder}/webpage/{json_filename}"
            
            # Create JSON content with the same structure as the original
            json_content = {
                'webpage_url': webpage_url,
                'unique_id': unique_id,
                'crawl_date': current_date.isoformat(),
                'total_documents': len(downloaded_files),
                'metadata': metadata,  # Include the crawl metadata (depth, page count, etc.)
                'documents': [
                    {
                        'filename': file_info['filename'],
                        'display_name': file_info['filename'],
                        'original_text': documents[i].get('text', '') if i < len(documents) else '',
                        'type': file_info['type'],
                        'size': file_info['size'],
                        'download_url': file_info['url'],
                        'blob_path': file_info['blob_path']
                    }
                    for i, file_info in enumerate(downloaded_files)
                ]
            }
            
            # Upload JSON metadata to Azure Storage or save locally
            json_data = json.dumps(json_content, indent=2)
            
            if blob_container_client:
                try:
                    # Upload JSON to Azure Storage
                    json_blob_client = blob_container_client.get_blob_client(json_blob_path)
                    json_blob_client.upload_blob(
                        json_data.encode('utf-8'), 
                        overwrite=True,
                        content_settings=ContentSettings(content_type='application/json')
                    )
                    logging.info(f"⚡ IMMEDIATE JSON UPLOAD: {json_filename} to {json_blob_path}")
                    webpage_json_result = {'status': 'uploaded', 'path': json_blob_path}
                except Exception as json_upload_error:
                    logging.error(f"❌ Immediate JSON upload failed for {json_filename}: {str(json_upload_error)}")
                    webpage_json_result = {'status': 'failed', 'error': str(json_upload_error)}
            else:
                # Save JSON to local file system
                try:
                    json_local_path = os.path.join("downloads", json_blob_path)
                    os.makedirs(os.path.dirname(json_local_path), exist_ok=True)
                    
                    with open(json_local_path, 'w', encoding='utf-8') as f:
                        f.write(json_data)
                    logging.info(f"⚡ IMMEDIATE JSON SAVE: {json_filename} to {json_local_path}")
                    webpage_json_result = {'status': 'saved_locally', 'path': json_local_path}
                except Exception as json_local_error:
                    logging.error(f"❌ Immediate JSON local save failed for {json_filename}: {str(json_local_error)}")
                    webpage_json_result = {'status': 'failed', 'error': str(json_local_error)}
                    
        except Exception as json_error:
            logging.error(f"❌ JSON metadata creation failed: {str(json_error)}")
            webpage_json_result = {'status': 'failed', 'error': str(json_error)}
    
    return {
        'webpage_url': webpage_url,
        'downloaded_files': downloaded_files,
        'failed_downloads': failed_downloads,
        'webpage_json_result': webpage_json_result,
        'immediate_upload': True
    }

# Activity Function 3: Process webpage documents
@app.activity_trigger(input_name="webpage_data")
def process_webpage_documents(webpage_data: dict) -> dict:
    """Activity function to process and upload documents from a specific webpage."""
    webpage_url = webpage_data["webpage_url"]
    documents = webpage_data["documents"]
    webpage_folder = webpage_data["webpage_folder"]
    
    logging.info(f"Processing documents for webpage: {webpage_url}")
    
    # Initialize Azure Blob Storage client
    blob_container_client = None
    try:
        # Get storage credentials
        account_name = get_secret_from_keyvault("AzureStorageAccountName")
        account_key = get_secret_from_keyvault("AzureStorageAccountKey")
        container_name = get_secret_from_keyvault("AzureStorageContainerName")
        
        # Check if we have valid storage account name
        if account_name and container_name:
            # Initialize blob service client with Azure AD authentication (no keys needed)
            try:
                credential = DefaultAzureCredential()
                blob_service_client = BlobServiceClient(
                    account_url=f"https://{account_name}.blob.core.windows.net",
                    credential=credential
                )
            except Exception as auth_error:
                logging.error(f"Azure AD authentication failed: {str(auth_error)}")
                # Fall back to local storage if authentication fails
                blob_service_client = None
            
            if blob_service_client:
                blob_container_client = blob_service_client.get_container_client(container_name)
                logging.info(f"Azure Storage initialized with AAD authentication: {container_name}")
                
                # Ensure container exists
                try:
                    blob_container_client.create_container()
                    logging.info(f"Container '{container_name}' created or already exists")
                except Exception as container_error:
                    # Container might already exist, which is fine
                    if "ContainerAlreadyExists" not in str(container_error):
                        logging.warning(f"Container creation info: {str(container_error)}")
            else:
                logging.warning("Azure AD authentication failed - falling back to LOCAL FILE SYSTEM mode")
        else:
            logging.warning("Azure Storage credentials not found - running in LOCAL FILE SYSTEM mode")
                
    except Exception as e:
        logging.error(f"Failed to initialize Azure Storage: {str(e)} - running in LOCAL FILE SYSTEM mode")
    
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

                # Upload to Azure Storage or simulate if not available
                if blob_container_client:
                    try:
                        # Actually upload to Azure Storage
                        blob_client = blob_container_client.get_blob_client(blob_path)
                        blob_client.upload_blob(
                            response.content, 
                            overwrite=True,
                            content_settings=ContentSettings(content_type='application/pdf' if ext == '.pdf' else 'application/octet-stream')
                        )
                        logging.info(f"✅ UPLOADED: {filename} ({len(response.content)} bytes) to {blob_path}")
                    except Exception as upload_error:
                        logging.error(f"❌ Upload failed for {filename}: {str(upload_error)}")
                        # Continue processing even if one upload fails
                else:
                    # Save to local file system if Azure Storage not available
                    try:
                        local_path = os.path.join("downloads", blob_path)
                        os.makedirs(os.path.dirname(local_path), exist_ok=True)
                        
                        with open(local_path, 'wb') as f:
                            f.write(response.content)
                        logging.info(f"💾 LOCAL SAVED: {filename} ({len(response.content)} bytes) to {local_path}")
                    except Exception as local_error:
                        logging.error(f"❌ Local save failed for {filename}: {str(local_error)}")

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
            
            # Upload JSON to Azure Storage or simulate if not available
            json_data = json.dumps(json_content, indent=2)
            
            if blob_container_client:
                try:
                    # Actually upload JSON to Azure Storage
                    json_blob_client = blob_container_client.get_blob_client(json_blob_path)
                    json_blob_client.upload_blob(
                        json_data.encode('utf-8'), 
                        overwrite=True,
                        content_settings=ContentSettings(content_type='application/json')
                    )
                    logging.info(f"✅ JSON UPLOADED: {json_filename} to {json_blob_path}")
                except Exception as json_upload_error:
                    logging.error(f"❌ JSON upload failed for {json_filename}: {str(json_upload_error)}")
            else:
                # Save JSON to local file system
                try:
                    json_local_path = os.path.join("downloads", json_blob_path)
                    os.makedirs(os.path.dirname(json_local_path), exist_ok=True)
                    
                    with open(json_local_path, 'w', encoding='utf-8') as f:
                        f.write(json_data)
                    logging.info(f"💾 JSON LOCAL SAVED: {json_filename} to {json_local_path}")
                except Exception as json_local_error:
                    logging.error(f"❌ JSON local save failed for {json_filename}: {str(json_local_error)}")
            
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
    response_text = f"🎉 DURABLE FUNCTIONS UNLIMITED WEB CRAWLER COMPLETED! 🎉\n\n"
    response_text += f"📘 Crawl Summary ({date_folder}):\n"
    response_text += f"⏱️ Duration: {start_time} to {end_time}\n"
    response_text += f"📄 Pages crawled: {crawl_info['pages_crawled']} (NO LIMITS!)\n"
    response_text += f"📋 Documents discovered: {crawl_info['documents_discovered']}\n"
    response_text += f"🔄 Webpages with changes: {len(change_detection['webpages_to_process'])}\n"
    response_text += f"⚪ Webpages unchanged: {len(change_detection['unchanged_webpages'])}\n"
    response_text += f"✅ Successfully processed: {total_downloaded} files\n"
    response_text += f"📄 Webpage JSON files created: {len(webpage_json_files)} files\n"
    response_text += f"❌ Failed downloads: {total_failed} files\n\n"
    
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
