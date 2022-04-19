============
Installation
============

Install the latest release with pip::

    $ pip install ndn-bootstrap

Install the latest development version::

    $ pip install -U git+https://github.com/tianyuan129/ndn-bootstrap.git

Instructions for developer
--------------------------

For development, pipenv is recommended::

    $ pipenv install --dev

To setup a traditional python3 virtual environment with editable installation:

.. code-block:: bash

    python3 -m venv venv
    . venv/bin/activate
    pip3 install -e ".[dev]"
