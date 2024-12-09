from setuptools import setup, find_packages

setup(
    name="bettercheck",
    version="0.0.1",
    packages=find_packages(),
    install_requires=[
        "requests",
        "click",
        "packaging",
        "pygithub",
        "pypistats",
        "jsonschema",
    ],
    entry_points={
        "console_scripts": [
            "bettercheck-yourself=bettercheck.check_yourself:main",
            "bettercheck=bettercheck.cli:main",
        ],
    },
)
