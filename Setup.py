from setuptools import setup, find_packages

setup(
    name="bettercheck",
    version="0.0.1",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        "requests",
        "click",
        "packaging",
        "pygithub",
        "pypistats",
        "jsonschema",
        "aiohttp",
        "dataclasses",
        "setuptools",
    ],
    entry_points={
        "console_scripts": [
            "bettercheck-yourself=bettercheck.check_yourself:main",
            "bettercheck=bettercheck.cli:main", 
            "bettercheck-deps=bettercheck.dep_tree:main",
        ]
    },
    python_requires=">=3.8",
)