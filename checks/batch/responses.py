from django.http import JsonResponse, HttpResponse

from . import BATCH_API_FULL_VERSION, BATCH_API_MAJOR_VERSION


def api_response(data, status_code=200):
    data.update({"api_version": BATCH_API_FULL_VERSION})
    json = JsonResponse(data)
    json.status_code = status_code
    return json


def unknown_request_response():
    return api_response({
        "error":
            {
                "label": "unknown-request",
                "msg": "This request_id does not exist for the user."
            }},
        status_code=404)


def unauthorised_response():
    resp = HttpResponse()
    resp.status_code = 401
    return resp


def bad_client_request_response(text):
    return api_response({
        "error":
            {
                "label": "bad-request",
                "msg": text
            }},
        status_code=400)


def general_server_error_response(
        text="General server error. Please report this if it keeps happening"):
    return api_response({
        "error":
            {
                "label": "server-error",
                "msg": text
            }},
        status_code=500)


def invalid_url_response():
    return api_response({
        "error":
            {
                "label": "invalid-url",
                "msg": (
                    f"Make sure you are using a valid URL and the current "
                    f"batch API version ({BATCH_API_MAJOR_VERSION})")
            }},
        status_code=400)
