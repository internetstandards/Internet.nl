# To export reports as Django fixtures and generate documentation urls

# on server
*DO NOT RUN ON PRODUCTION DB, WILL CAUSE DATA LOSS!*

`ssh <server>`
`docker compose --project-name=internetnl-prod exec postgres psql --username internetnl internetnl_db1`

    # clear existing reports and related data
    delete from checks_asrecord;
    delete from checks_autoconf;
    delete from checks_batchdomain;
    delete from checks_batchmailtest;
    delete from checks_batchrequest;
    delete from checks_batchuser;
    delete from checks_batchwebtest;
    delete from checks_connectiontest;
    delete from checks_domaintestappsecpriv;
    delete from checks_domaintestdnssec;
    delete from checks_domaintestipv6;
    delete from checks_domaintestreport;
    delete from checks_domaintesttls;
    delete from checks_mailtestauth;
    delete from checks_mailtestdnssec;
    delete from checks_mailtestipv6;
    delete from checks_mailtestreport;
    delete from checks_mailtestrpki;
    delete from checks_mailtesttls;
    delete from checks_mxdomain;
    delete from checks_nsdomain;
    delete from checks_resolver;
    delete from checks_rpkimxhost;
    delete from checks_rpkimxnshost;
    delete from checks_rpkinshost;
    delete from checks_rpkiwebhost;
    delete from checks_webdomain;
    delete from checks_webtestappsecpriv;
    delete from checks_webtestrpki;
    delete from checks_webtesttls;

    # set starting index as a high number to avoid conflicts with existing reports on import
    alter sequence checks_asrecord_id_seq RESTART with 9000;
    alter sequence checks_autoconf_id_seq RESTART with 9000;
    alter sequence checks_batchdomain_id_seq RESTART with 9000;
    alter sequence checks_batchmailtest_id_seq RESTART with 9000;
    alter sequence checks_batchrequest_id_seq RESTART with 9000;
    alter sequence checks_batchuser_id_seq RESTART with 9000;
    alter sequence checks_batchwebtest_id_seq RESTART with 9000;
    alter sequence checks_connectiontest_id_seq RESTART with 9000;
    alter sequence checks_domaintestappsecpriv_id_seq RESTART with 9000;
    alter sequence checks_domaintestdnssec_id_seq RESTART with 9000;
    alter sequence checks_domaintestipv6_id_seq RESTART with 9000;
    alter sequence checks_domaintestreport_id_seq RESTART with 9000;
    alter sequence checks_domaintesttls_id_seq RESTART with 9000;
    alter sequence checks_mailtestauth_id_seq RESTART with 9000;
    alter sequence checks_mailtestdnssec_id_seq RESTART with 9000;
    alter sequence checks_mailtestipv6_id_seq RESTART with 9000;
    alter sequence checks_mailtestreport_id_seq RESTART with 9000;
    alter sequence checks_mailtestrpki_id_seq RESTART with 9000;
    alter sequence checks_mailtesttls_id_seq RESTART with 9000;
    alter sequence checks_mxdomain_id_seq RESTART with 9000;
    alter sequence checks_nsdomain_id_seq RESTART with 9000;
    alter sequence checks_resolver_id_seq RESTART with 9000;
    alter sequence checks_rpkimxhost_id_seq RESTART with 9000;
    alter sequence checks_rpkimxnshost_id_seq RESTART with 9000;
    alter sequence checks_rpkinshost_id_seq RESTART with 9000;
    alter sequence checks_rpkiwebhost_id_seq RESTART with 9000;
    alter sequence checks_webdomain_id_seq RESTART with 9000;
    alter sequence checks_webtestappsecpriv_id_seq RESTART with 9000;
    alter sequence checks_webtestrpki_id_seq RESTART with 9000;
    alter sequence checks_webtesttls_id_seq RESTART with 9000;

## run live tests to generate reports
`APP_URLS=https://<server> RELEASE=latest make live-tests`

## export fixtures
`docker compose --project-name=internetnl-prod exec app ./manage.py dumpdata checks --indent=2 > ~/example_reports.json`

# in local dev
`scp <server>:example_reports.json checks/fixtures/`

## import fixtures
`docker exec -ti internetnl-develop-app-1 ./manage.py loaddata example_reports.json`

## generate documentation urls
`docker exec -ti internetnl-develop-app-1 ./manage.py shell`

    from checks.models import DomainTestReport, MailTestReport, ConnectionTest
    for d in DomainTestReport.objects.all():
        print(f"http://localhost:8080/site/{d.domain}/{d.id}/")

    for d in MailTestReport.objects.all():
        print(f"http://localhost:8080/mail/{d.domain}/{d.id}/")

    for d in ConnectionTest.objects.all():
        print(f"http://localhost:8080/connection/{d.test_id}/")
