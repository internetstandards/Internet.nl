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

To add a new menu entry for a new language set the `LANGUAGES` setting in `local.env`. The default is `nl,en`. You can add new languages by adding languages codes supported by Django:
- https://docs.djangoproject.com/en/5.0/ref/settings/#std-setting-LANGUAGE_CODE
- http://www.i18nguy.com/unicode/language-identifiers.html

The first language in the list is the default langauge.

So to add French and use it as the default languages set it to:

    LANGUAGES=fr,nl,en

This presumes you have the corresponding DNS entries already created, such as

```
[lang].example.nl
[lang].ipv6.example.nl
[lang].conn.example.nl
[lang].conn.ipv6.example.nl
```

where [lang] is the language code added to LANGUAGE.

You can remove languages you don't intend to support.

Then, update the site using the procedure in [documentation/Docker-forked.md](Docker-forked.md) to rebuild the front accordingly.

For `news.po` you can provide your own news/blogs but you need to follow the
existing conventions. (**FIXME**: this needs further clarification)

## Security.txt

To add a `.well-known/security.txt` file to your installation, create the file `.well-known/security-custom.txt` in the repository. The existing `.well-known/security.txt` file cannot be used.

After which the `webserver` image should be rebuild and will serve the file under the `/.well-known/security.txt` path.

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
