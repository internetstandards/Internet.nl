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

For `news.po` you can provide your own news/blogs but you need to follow the
existing conventions.


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
