def print_details_test_results(page):
    """Print detail test results from the result page for debugging failed tests."""
    try:
        # for debugging failed tests
        for section in page.locator("section.test-header").all():
            section.get_by_role("button", name="Show details").click()
        for section in page.locator("section.testresults").all():
            print(section.inner_text())
    except Exception:
        # don't fail the test if we somehow failed to get the test result details debug information
        print("Failed to gather detailed test results.")
