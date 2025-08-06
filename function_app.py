import azure.functions as func
import logging
import requests
from bs4 import BeautifulSoup
import os
import tempfile
import time
from urllib.parse import urljoin

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="download_pdf_func")
def download_pdf_func(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Function triggered to scrape and download PDF.')

    # URL to scrape
    target_url = 'https://rulebook.centralbank.ae/en/rulebook/standards-regulations-regarding-licensing-and-monitoring-exchange-business'

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
        # Step 1: Get HTML content
        logging.info('Fetching webpage...')
        response = session.get(target_url, timeout=30)
        
        if response.status_code != 200:
            logging.error(f'Failed to fetch page. Status code: {response.status_code}')
            return func.HttpResponse(f"Failed to fetch page. Status: {response.status_code}", status_code=500)

        # Step 2: Parse HTML to find download links
        logging.info('Parsing HTML for PDF links...')
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Look for PDF links more comprehensively
        pdf_links = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            text = a.text.strip().lower()
            
            if href.endswith('.pdf') or 'pdf' in href.lower():
                pdf_links.append({'url': href, 'text': text})
            elif any(keyword in text for keyword in ['download', 'pdf', 'document']):
                pdf_links.append({'url': href, 'text': text})

        if not pdf_links:
            logging.warning('No PDF links found')
            return func.HttpResponse("No PDF links found on the page", status_code=404)

        logging.info(f'Found {len(pdf_links)} PDF links')

        # Try to download the first PDF link
        pdf_info = pdf_links[0]
        if not pdf_info['url'].startswith('http'):
            download_url = urljoin(target_url, pdf_info['url'])
        else:
            download_url = pdf_info['url']

        logging.info(f'Attempting to download: {download_url}')

        # Try download with enhanced session
        pdf_response = session.get(download_url, timeout=30)
        
        if pdf_response.status_code != 200:
            # Try with referer
            session.headers.update({'Referer': 'https://rulebook.centralbank.ae/'})
            pdf_response = session.get(download_url, timeout=30)

        if pdf_response.status_code == 200 and len(pdf_response.content) > 1000:
            # Create downloads directory
            downloads_dir = os.path.join(os.getcwd(), "downloads")
            os.makedirs(downloads_dir, exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = int(time.time())
            filename = f"CBUAE_rulebook_{timestamp}.pdf"
            filepath = os.path.join(downloads_dir, filename)
            
            # Save the file
            with open(filepath, 'wb') as f:
                f.write(pdf_response.content)
            
            logging.info(f'PDF saved to {filepath}')
            return func.HttpResponse(
                f"✅ PDF downloaded successfully!\n"
                f"📁 Saved to: {filepath}\n"
                f"📊 Size: {len(pdf_response.content):,} bytes\n"
                f"🌐 Source: {download_url}", 
                status_code=200
            )
        else:
            # Return information about found links even if download failed
            links_info = "\n".join([f"- {link['text']}: {link['url']}" for link in pdf_links[:3]])
            return func.HttpResponse(
                f"Found PDF links but download failed (Status: {pdf_response.status_code}).\n"
                f"Available links:\n{links_info}", 
                status_code=202
            )

    except Exception as e:
        logging.error(f'Error occurred: {str(e)}')
        return func.HttpResponse(f"Error occurred: {str(e)}", status_code=500)