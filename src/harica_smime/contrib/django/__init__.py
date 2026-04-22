"""Django app shipping the browser-side static assets for harica_smime.

Add ``"harica_smime.contrib.django"`` to your project's ``INSTALLED_APPS`` and
Django's ``AppDirectoriesFinder`` will pick up the bundled JavaScript under
the ``harica_smime/`` static-file prefix::

    {% static 'harica_smime/forge.min.js' %}
    {% static 'harica_smime/harica-smime-crypto.js' %}

Importing this package requires Django; install the optional extra with::

    pip install "harica-smime[django]"
"""
