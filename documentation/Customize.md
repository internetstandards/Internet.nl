# Customization

The Internet.nl tool has the ability to be customized for additional
translations and content.


## Translations

Translation files are available under `translations/<locale>`.

The available files are:
- `main.po`, all the necessary strings to make internet.nl work;
- `news.po`, all the news/blog entries.

You can add new locales by creating a new folder under `translations` and
adding the above files.

You need to translate all the strings in `main.po`.

To add a new meny entry for the new language, you also need to update the file

`internet.nl/settings.py`

and to have the webserver correctly route the traffic to the newly created
language and correctly create the LE certificates the

`webserver/nginx_templates/app.conf.template`

needs to be updated according in various places. This also presumes you
have the corresponding DNS entries already created, such as

```
[lang].example.nl
[lang].fr.ipv6.example.nl
[lang].conn.example.nl
[lang].conn.ipv6.example.nl
```

where [lang] is the 2 letter ISO 639-1 language code.

Then, update the site using the procedure in [documentation/Docker-forked.md](Docker-forked.md) to rebuild the front accordingly.

For `news.po` you can provide your own news/blogs but you need to follow the
existing conventions. (**FIXME**: this needs further clarification)


## Scores

You can alter the scores and the requirement level of each test by editing the
[scoring.py](../checks/scoring.py) file.

Make sure to carefully read the comments in that file so that you understand
the effects of your edits.


## CSS

CSS customization is not there yet. The logic is there but we still need to
export all the used styles for easier configuration.

For now you can change the CSS files under `frontend/css/`.

Make sure that you run
```
make frontend css
```
to generate minified versions ready for deployment.
