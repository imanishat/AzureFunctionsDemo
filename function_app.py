import azure.functions as func
import logging
import requests
from bs4 import BeautifulSoup
import os
import tempfile
import time
from urllib.parse import urljoin, urlparse
from collections import deque
import re

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="download_multiple_files")
def download_multiple_files(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Function triggered to crawl and download all PDF and Word document files.')

    # Configuration
    target_url = 'https://rulebook.centralbank.ae/en'
    max_pages_to_crawl = 10  # Limit to prevent infinite crawling
    max_depth = 2  # How many levels deep to crawl
    
    # Enhanced headers to better mimic a real browser
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
    })

    try:
        # Get base domain for filtering
        base_domain = urlparse(target_url).netloc
        
        # Initialize crawling data structures
        urls_to_visit = deque([(target_url, 0)])  # (url, depth)
        visited_urls = set()
        all_document_links = []
        crawl_summary = []

        logging.info(f'Starting crawl of {target_url} (max depth: {max_depth}, max pages: {max_pages_to_crawl})')

        # Crawl through pages
        pages_crawled = 0
        while urls_to_visit and pages_crawled < max_pages_to_crawl:
            current_url, depth = urls_to_visit.popleft()
            
            # Skip if already visited or too deep
            if current_url in visited_urls or depth > max_depth:
                continue
                
            visited_urls.add(current_url)
            pages_crawled += 1
            
            logging.info(f'Crawling page {pages_crawled}/{max_pages_to_crawl}: {current_url} (depth: {depth})')
            
            try:
                # Fetch the page
                response = session.get(current_url, timeout=30)
                if response.status_code != 200:
                    logging.warning(f'Failed to fetch {current_url}: Status {response.status_code}')
                    continue

                # Parse HTML
                soup = BeautifulSoup(response.content, 'html.parser')
                page_document_links = []
                page_navigation_links = []

                # Find all links on this page
                for a in soup.find_all('a', href=True):
                    href = a['href']
                    text = a.text.strip()
                    
                    # Convert relative URLs to absolute
                    if not href.startswith('http'):
                        full_url = urljoin(current_url, href)
                    else:
                        full_url = href
                    
                    # Check if it's a document link
                    is_document = False
                    doc_type = None
                    
                    # Check for PDF files
                    if (href.endswith('.pdf') or 'pdf' in href.lower() or 
                        any(keyword in text.lower() for keyword in ['pdf', 'download pdf'])):
                        is_document = True
                        doc_type = 'PDF'
                    
                    # Check for Word files
                    elif (href.endswith(('.doc', '.docx')) or 
                          any(ext in href.lower() for ext in ['doc', 'docx']) or
                          any(keyword in text.lower() for keyword in ['word', 'doc', 'docx'])):
                        is_document = True
                        doc_type = 'Word'
                    
                    if is_document:
                        page_document_links.append({
                            'url': full_url,
                            'text': text,
                            'type': doc_type,
                            'source_page': current_url
                        })
                    
                    # Check if it's a navigation link to explore further
                    elif (depth < max_depth and 
                          urlparse(full_url).netloc == base_domain and  # Same domain
                          full_url not in visited_urls and
                          not any(skip in full_url.lower() for skip in ['javascript:', 'mailto:', '#', '.jpg', '.png', '.gif', '.css', '.js'])):
                        page_navigation_links.append(full_url)

                # Add found documents to our collection
                all_document_links.extend(page_document_links)
                
                # Add navigation links for further crawling
                for nav_url in page_navigation_links:
                    urls_to_visit.append((nav_url, depth + 1))

                crawl_summary.append({
                    'url': current_url,
                    'depth': depth,
                    'documents_found': len(page_document_links),
                    'navigation_links': len(page_navigation_links)
                })
                
                logging.info(f'Page {current_url}: Found {len(page_document_links)} documents, {len(page_navigation_links)} navigation links')
                
                # Small delay between page requests
                time.sleep(1)
                
            except Exception as e:
                logging.error(f'Error crawling {current_url}: {str(e)}')
                continue

        logging.info(f'Crawling complete. Visited {len(visited_urls)} pages, found {len(all_document_links)} documents')

        if not all_document_links:
            return func.HttpResponse("No documents found during crawling", status_code=404)

        # Now download all found documents
        logging.info(f'Starting download of {len(all_document_links)} documents')
        
        # Create downloads directory
        downloads_dir = os.path.join(os.getcwd(), "downloads")
        os.makedirs(downloads_dir, exist_ok=True)
        
        # Download all document files
        downloaded_files = []
        failed_downloads = []
        
        for i, doc_info in enumerate(all_document_links):
            try:
                download_url = doc_info['url']
                logging.info(f'Attempting to download {i+1}/{len(all_document_links)} ({doc_info["type"]}): {download_url}')

                # Try download with enhanced session
                doc_response = session.get(download_url, timeout=30)
                
                if doc_response.status_code != 200:
                    # Try with referer from source page
                    session.headers.update({'Referer': doc_info['source_page']})
                    doc_response = session.get(download_url, timeout=30)

                if doc_response.status_code == 200 and len(doc_response.content) > 1000:
                    # Generate filename with timestamp and index
                    timestamp = int(time.time())
                    
                    # Try to extract meaningful filename from URL or text
                    url_filename = download_url.split('/')[-1] if any(download_url.split('/')[-1].endswith(ext) for ext in ['.pdf', '.doc', '.docx']) else None
                    text_clean = ''.join(c for c in doc_info['text'][:30] if c.isalnum() or c in ' -_').strip()
                    
                    # Determine file extension based on type and URL
                    if url_filename:
                        filename = f"{timestamp}_{i+1}_{url_filename}"
                    elif text_clean:
                        if doc_info['type'] == 'Word':
                            ext = '.docx' if 'docx' in download_url.lower() else '.doc'
                        else:
                            ext = '.pdf'
                        filename = f"SCA_{text_clean.replace(' ', '_')}_{timestamp}_{i+1}{ext}"
                    else:
                        if doc_info['type'] == 'Word':
                            ext = '.docx' if 'docx' in download_url.lower() else '.doc'
                        else:
                            ext = '.pdf'
                        filename = f"SCA_document_{timestamp}_{i+1}{ext}"
                    
                    filepath = os.path.join(downloads_dir, filename)
                    
                    # Save the file
                    with open(filepath, 'wb') as f:
                        f.write(doc_response.content)
                    
                    downloaded_files.append({
                        'filename': filename,
                        'size': len(doc_response.content),
                        'url': download_url,
                        'text': doc_info['text'],
                        'type': doc_info['type'],
                        'source_page': doc_info['source_page']
                    })
                    
                    logging.info(f'{doc_info["type"]} saved to {filepath} ({len(doc_response.content):,} bytes)')
                    
                    # Small delay between downloads to be respectful
                    time.sleep(1)
                    
                else:
                    failed_downloads.append({
                        'url': download_url,
                        'text': doc_info['text'],
                        'type': doc_info['type'],
                        'source_page': doc_info['source_page'],
                        'status': doc_response.status_code,
                        'size': len(doc_response.content) if doc_response.content else 0
                    })
                    
            except Exception as e:
                logging.error(f'Error downloading {download_url}: {str(e)}')
                failed_downloads.append({
                    'url': download_url,
                    'text': doc_info['text'],
                    'type': doc_info['type'],
                    'source_page': doc_info['source_page'],
                    'error': str(e)
                })

        # Prepare comprehensive response summary
        response_text = f"� Crawl Summary:\n"
        response_text += f"📄 Pages crawled: {len(visited_urls)}\n"
        response_text += f"📋 Documents discovered: {len(all_document_links)}\n"
        response_text += f"✅ Successfully downloaded: {len(downloaded_files)} files\n"
        response_text += f"❌ Failed downloads: {len(failed_downloads)} files\n\n"
        
        if downloaded_files:
            response_text += "📁 Downloaded Files:\n"
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
            response_text += f"\n📦 Total downloaded: {total_size:,} bytes\n"
        
        if failed_downloads:
            response_text += "\n❌ Failed Downloads:\n"
            for fail_info in failed_downloads:
                type_icon = "📄" if fail_info['type'] == 'PDF' else "📝"
                response_text += f"  {type_icon} {fail_info['text'][:50]}{'...' if len(fail_info['text']) > 50 else ''}\n"
                if 'error' in fail_info:
                    response_text += f"    ❗ Error: {fail_info['error']}\n"
                else:
                    response_text += f"    ❗ Status: {fail_info['status']}, Size: {fail_info['size']} bytes\n"

        # Add crawl details
        response_text += f"\n🔍 Crawl Details:\n"
        for summary in crawl_summary:
            response_text += f"  • {urlparse(summary['url']).path} (depth {summary['depth']}): {summary['documents_found']} docs\n"

        if downloaded_files:
            return func.HttpResponse(response_text, status_code=200)
        else:
            return func.HttpResponse(f"No files could be downloaded.\n{response_text}", status_code=202)

    except Exception as e:
        logging.error(f'Error occurred: {str(e)}')
        return func.HttpResponse(f"Error occurred: {str(e)}", status_code=500)