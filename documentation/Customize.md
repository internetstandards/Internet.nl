# Customization

The Internet.nl tool has the ability to be customized for additional
translations and content.

## Translations

Translation files are available under `translations/<locale>`.

The available files are:
- `main.po`, all the necessary strings to make internet.nl work;
- `news.po`, all the news/blog entries.

You can add new locales by creating a new folder and `translations` and adding
the above files.


## CSS

CSS customization is not there yet. The logic is there but we still need to
export all the used styles for easier configuration.

For now you can change the CSS files under `frontend/css/`.

Make sure that you run
```
make frontend css
```
to generate minified versions ready for deployment.
