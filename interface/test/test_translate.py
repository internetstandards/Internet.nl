from django.template import Context, Template


def test_translate_attr_escapes_quotes():
    template = Template("""{% load translate %}<img alt="{% translate_attr 'a "quoted" text' %}">""")
    assert template.render(Context()) == '<img alt="a &quot;quoted&quot; text">'
