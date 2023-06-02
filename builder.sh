#!/bin/bash

python -m build
python -m twine upload --repository pypi dist/*
