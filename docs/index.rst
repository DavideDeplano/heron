heron
=====

Phishing email triage: heron reads ``.eml`` files and gives each message a
verdict (benign, suspicious or phishing) with the findings behind it.

.. code-block:: bash

   uv sync                      # install heron and the dev tools from uv.lock
   uv run heron data/samples    # one verdict per message, then a summary

.. toctree::

   modules
