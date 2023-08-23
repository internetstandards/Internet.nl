# Get API version from the batch code to update section in the documentation
from interface.batch import BATCH_API_FULL_VERSION

# explicitly declare the imported value, otherwise pyflakes thinks this is an unused variable
__all__ = BATCH_API_FULL_VERSION  #


# These values will update/replace values in the API documentation when the
# manage.py api_generate_doc command is used.
# Leave empty [''] if you want to skip something.

#
# These values will update sections in the documentation.
#
TITLE = "Internet.nl Batch API"
TERMS = ""
CONTACT = {"name": "Internet.nl Help desk", "email": "vraag@internet.nl"}
LOGO = {
    "url": "https://batch.internet.nl/static/logo_en.svg",
    "backgroundColor": "#FAFAFA",
    "altText": "Internet.nl logo",
}
SERVERS = [
    {"url": "https://batch.internet.nl/api/batch/v2", "description": "Production server"},
    {
        "url": "https://dev.batch.internet.nl/api/batch/v2",
        "description": "Development server (data longevity is not guaranteed)",
    },
]

#
# These values will replace text in the documentation.
#
DESC_INTRO_REDOCLY_LINK = "https://batch.internet.nl/api/batch/openapi.yaml"
DESC_INTRO_EXTRA = """
## Requesting access

Instructions and more information can be found here: [https://github.com/internetstandards/Internet.nl-API-docs/tree/main/application_form](https://github.com/internetstandards/Internet.nl-API-docs/tree/main/application_form).

## Dashboard or API?

Internet.nl provides a dashboard. If you don't want to implement this API, but
do want batch scanning, this is the option for you. The dashboard comes with a
series of features that you might convenient. Such as:

* periodical batch scans

* domain and list management

* scan tracking

* extensive reporting, including:

  * comparisons to other reports

  * graphs

  * metrics in tables

* export options (excel, ods, csv)


Requesting access to the dashboard can be done by contacting the help desk.
"""  # noqa: E501
