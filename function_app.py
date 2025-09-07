import azure.functions as func
import logging
import requests
from bs4 import BeautifulSoup
import os
import time
from urllib.parse import urljoin, urlparse
from collections import deque
import hashlib
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
        max_pages_to_crawl = 10
        max_depth = 2

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

        # Use DefaultAzureCredential for managed identity authentication
        credential = DefaultAzureCredential()

        blob_service_client = BlobServiceClient(
            account_url=f"https://{account_name}.blob.core.windows.net",
            credential=credential
        )
        blob_container_client = blob_service_client.get_container_client(container_name)

        downloaded_files = []
        failed_downloads = []
        uploaded_hashes = set()

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

        # Begin Uploads
        for i, doc_info in enumerate(all_document_links):
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
                    uploaded_hashes.add(content_hash)

                    ext = ".pdf" if doc_info['type'] == 'PDF' else (".docx" if 'docx' in download_url else ".doc")
                    timestamp = int(time.time())
                    safe_text = ''.join(c for c in doc_info['text'][:50] if c.isalnum() or c in ' -_').strip().replace(' ', '_')
                    filename = f"{safe_text}_{timestamp}_{i+1}{ext}" if safe_text else f"document_{timestamp}_{i+1}{ext}"
                    blob_path = f"{doc_info['type'].lower()}s/{filename}"

                    blob_container_client.upload_blob(
                        name=blob_path,
                        data=response.content,
                        overwrite=False
                    )

                    downloaded_files.append({
                        'filename': filename,
                        'size': len(response.content),
                        'url': download_url,
                        'text': doc_info['text'],
                        'type': doc_info['type'],
                        'source_page': doc_info['source_page']
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

        # 📋 Prepare Summary
        response_text = f"📘 Crawl Summary:\n"
        response_text += f"📄 Pages crawled: {len(visited_urls)}\n"
        response_text += f"📋 Documents discovered: {len(all_document_links)}\n"
        response_text += f"✅ Successfully uploaded: {len(downloaded_files)} files\n"
        response_text += f"❌ Failed uploads: {len(failed_downloads)} files\n\n"

        if downloaded_files:
            response_text += "📁 Uploaded Files:\n"
            total_size = 0
            pdf_count = sum(1 for f in downloaded_files if f['type'] == 'PDF')
            word_count = sum(1 for f in downloaded_files if f['type'] == 'Word')
            response_text += f"   📊 {pdf_count} PDF files, {word_count} Word files\n\n"

            for file_info in downloaded_files:
                type_icon = "📄" if file_info['type'] == 'PDF' else "📝"
                response_text += f"  {type_icon} {file_info['filename']} ({file_info['size']:,} bytes)\n"
                response_text += f"    📝 {file_info['text'][:50]}{'...' if len(file_info['text']) > 50 else ''}\n"
                response_text += f"    🔗 Source: {urlparse(file_info['source_page']).path}\n"
                total_size += file_info['size']
            response_text += f"\n📦 Total uploaded: {total_size:,} bytes (~{total_size/1024/1024:.2f} MB)\n"

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
