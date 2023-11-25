# pyThreatCode

![Tests](https://github.com/threatcode/pyThreatCode/actions/workflows/test.yml/badge.svg)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

`pyThreatCode` is a python library that parses and converts ThreatCode rules into queries. It is a replacement
for the legacy ThreatCode toolchain (threatcodec) with a much cleaner design and is almost fully tested.
Backends for support of conversion into query languages and processing pipelines for transforming
rule for log data models are separated into dedicated projects to keep pyThreatCode itself slim and
vendor-agnostic. See the *Related Projects* section below to get an overview.

## Getting Started

To start using `pyThreatCode`, install it using your python package manager of choice. Examples:

```
pip install pythreatcode
pipenv install pythreatcode
poetry add pythreatcode
```
