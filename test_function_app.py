import azure.functions as func
import logging

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="test")
def test_function(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Simple test function triggered.')
    return func.HttpResponse("Hello from Azure Functions! The function is working.", status_code=200)
