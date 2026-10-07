"""Sphinx configuration: build the heron docs from the docstrings."""

project = "heron"
extensions = [
    "sphinx.ext.autodoc",  # read the docstrings of the modules
    "sphinx.ext.napoleon",  # understand the NumPy-style sections
]
napoleon_google_docstring = False  # this project writes NumPy style only
html_theme = "sphinx_rtd_theme"
exclude_patterns = ["_build"]
