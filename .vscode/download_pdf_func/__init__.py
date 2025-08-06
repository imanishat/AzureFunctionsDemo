import logging
import requests
from bs4 import BeautifulSoup
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Function triggered to scrape and download PDF.')

    # URL to scrape
    target_url = 'https://rulebook.centralbank.ae/en/rulebook/standards-regulations-regarding-licensing-and-monitoring-exchange-business'

    try:
        # Step 1: Get HTML content
        response = requests.get(target_url)
        if response.status_code != 200:
            return func.HttpResponse("Failed to fetch page", status_code=500)

        # Step 2: Parse HTML to find download link
        soup = BeautifulSoup(response.content, 'html.parser')
        download_link = None

        # This depends on the website structure – here's a generic example:
        for a in soup.find_all('a', href=True):
            if 'download' in a.text.lower() or a['href'].endswith('.pdf'):
                download_link = a['href']
                break

        if not download_link:
            return func.HttpResponse("Download link not found", status_code=404)

        # Step 3: Handle relative URLs
        if not download_link.startswith('http'):
            from urllib.parse import urljoin
            download_link = urljoin(target_url, download_link)

        # Step 4: Download the PDF content
        pdf_response = requests.get(download_link)
        if pdf_response.status_code != 200:
            return func.HttpResponse("Failed to download PDF", status_code=500)

        # (Optional) Save to local temp file for now
        with open("/tmp/downloaded_file.pdf", "wb") as f:
            f.write(pdf_response.content)

        return func.HttpResponse(f"PDF downloaded successfully from {download_link}", status_code=200)

    except Exception as e:
        logging.error(str(e))
        return func.HttpResponse("Error occurred", status_code=500)
